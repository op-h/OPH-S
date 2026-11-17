//! Splunk-style search language compiled to parameterised SQL.
//!
//! `kind=dns.query host=192.168.1.* severity>=medium "free text" NOT process=svchost.exe
//!  | stats count by domain | head 20`
//!
//! Semantics follow Splunk: terms are ANDed, `OR` binds tighter than the
//! implicit AND, `NOT` negates the next term.

use rusqlite::types::Value;

pub const FIELDS: [&str; 10] = ["source", "kind", "severity", "host", "src_ip", "dst_ip", "dst_port", "domain", "process", "message"];

#[derive(Debug, Default)]
pub struct Compiled {
    pub where_sql: String,
    pub params: Vec<Value>,
    pub stats_by: Option<String>,
    pub stats_limit: usize,
    pub head: Option<usize>,
    pub asc: bool,
}

/// Nearest searchable field by edit distance (typo help), plus common synonyms.
pub fn closest_field(f: &str) -> Option<&'static str> {
    let syn: &[(&str, &str)] = &[("ip", "src_ip"), ("src", "src_ip"), ("dst", "dst_ip"), ("dest", "dst_ip"), ("port", "dst_port"),
        ("site", "domain"), ("url", "domain"), ("host_name", "host"), ("device", "host"), ("app", "process"), ("program", "process"),
        ("level", "severity"), ("sev", "severity"), ("type", "kind"), ("msg", "message"), ("text", "message")];
    if let Some((_, t)) = syn.iter().find(|(s, _)| *s == f) {
        return Some(t);
    }
    fn lev(a: &str, b: &str) -> usize {
        let b: Vec<char> = b.chars().collect();
        let mut prev: Vec<usize> = (0..=b.len()).collect();
        for (i, ca) in a.chars().enumerate() {
            let mut cur = vec![i + 1];
            for (j, cb) in b.iter().enumerate() {
                cur.push((prev[j] + (ca != *cb) as usize).min(prev[j + 1] + 1).min(cur[j] + 1));
            }
            prev = cur;
        }
        prev[b.len()]
    }
    FIELDS.iter().map(|x| (lev(f, x), *x)).filter(|(d, _)| *d <= 2).min().map(|(_, x)| x)
}

fn tokenize(q: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = q.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' => {
                // quoted span; keep quotes so the parser knows it was quoted
                cur.push('"');
                let mut closed = false;
                for c2 in chars.by_ref() {
                    if c2 == '"' {
                        closed = true;
                        break;
                    }
                    cur.push(c2);
                }
                if !closed {
                    return Err("Unterminated quote in search".into());
                }
                cur.push('"');
            }
            '|' => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
                out.push("|".into());
            }
            c if c.is_whitespace() => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    Ok(out)
}

fn unquote(s: &str) -> String {
    let t = s.strip_prefix('"').and_then(|x| x.strip_suffix('"')).unwrap_or(s);
    t.replace('"', "")
}

fn like_pattern(v: &str) -> String {
    let mut p = String::with_capacity(v.len() + 2);
    for ch in v.chars() {
        match ch {
            '%' | '_' | '\\' => {
                p.push('\\');
                p.push(ch);
            }
            '*' => p.push('%'),
            c => p.push(c),
        }
    }
    p
}

fn compile_term(tok: &str, params: &mut Vec<Value>) -> Result<String, String> {
    // field comparison?
    if !tok.starts_with('"') {
        for op in ["!=", ">=", "<=", "=", ">", "<"] {
            if let Some(i) = tok.find(op) {
                let field = tok[..i].trim().to_ascii_lowercase();
                let raw = unquote(&tok[i + op.len()..]);
                if field.is_empty() {
                    break;
                }
                if field == "vpn" {
                    // VPN: virtual field (hagezi VPN/proxy list + VPN-only ports + VPN client programs)
                    let on = matches!(raw.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on" | "*");
                    let want = if op == "!=" { !on } else { on };
                    return Ok(if want { "vpn(domain, dst_port, process) = 1".into() } else { "vpn(domain, dst_port, process) = 0".into() });
                }
                if field == "pd" {
                    // PD (porn detector): virtual field backed by the OISD NSFW list
                    let on = matches!(raw.to_ascii_lowercase().as_str(), "yes" | "true" | "1" | "on" | "*");
                    let want = if op == "!=" { !on } else { on };
                    return Ok(if want { "pd(domain) = 1".into() } else { "(domain IS NULL OR pd(domain) = 0)".into() });
                }
                if !FIELDS.contains(&field.as_str()) {
                    return Err(match closest_field(&field) {
                        Some(f) => format!("Unknown field \"{field}\". Did you mean \"{f}\"?"),
                        None => format!("Unknown field \"{field}\". Searchable fields: {}", FIELDS.join(", ")),
                    });
                }
                if field == "severity" && op != "=" && op != "!=" {
                    let rank = oph_proto::SEVERITIES
                        .iter()
                        .position(|s| *s == raw.to_ascii_lowercase())
                        .ok_or_else(|| format!("Unknown severity \"{raw}\". Use info, low, medium, high or critical"))?;
                    params.push(Value::Integer(rank as i64));
                    return Ok(format!("sev {op} ?"));
                }
                if field == "dst_port" && op != "=" && op != "!=" {
                    let n: i64 = raw.parse().map_err(|_| format!("dst_port{op} needs a number"))?;
                    params.push(Value::Integer(n));
                    return Ok(format!("dst_port {op} ?"));
                }
                if matches!(op, ">" | "<" | ">=" | "<=") {
                    return Err(format!("Operator {op} only works with severity and dst_port"));
                }
                let neg = op == "!=";
                if raw == "*" {
                    return Ok(format!("{field} IS {}NULL", if neg { "" } else { "NOT " }));
                }
                // enum-like fields are stored lower-case: compare directly so the index is used;
                // free-form fields compare through ulower() (Unicode-aware: É/é, Ü/ü, Arabic, ...)
                // ports are numbers: exact matches compare as integers (index-friendly)
                if field == "dst_port" && !raw.contains('*') {
                    let n: i64 = raw.trim().parse().map_err(|_| format!("dst_port needs a number, e.g. dst_port=443 (got \"{raw}\")"))?;
                    params.push(Value::Integer(n));
                    return Ok(if neg { "(dst_port IS NULL OR dst_port != ?)".into() } else { "dst_port = ?".into() });
                }
                let col = if matches!(field.as_str(), "kind" | "source" | "severity") { field.clone() } else { format!("ulower({field})") };
                let raw = raw.to_lowercase();
                if raw.contains('*') {
                    params.push(Value::Text(like_pattern(&raw)));
                    return Ok(format!("{}({col} LIKE ? ESCAPE '\\')", if neg { "NOT " } else { "" }));
                }
                params.push(Value::Text(raw));
                return Ok(if neg { format!("({field} IS NULL OR {col} != ?)") } else { format!("{col} = ?") });
            }
        }
    }
    // free text
    let text = unquote(tok);
    if text.is_empty() {
        return Ok("1".into());
    }
    // trim user wildcards *before* escaping, so a literal "50%" stays searchable
    let pat = format!("%{}%", like_pattern(&text.trim_matches('*').to_lowercase()));
    for _ in 0..4 {
        params.push(Value::Text(pat.clone()));
    }
    Ok("(ulower(message) LIKE ? ESCAPE '\\' OR ulower(domain) LIKE ? ESCAPE '\\' OR ulower(process) LIKE ? ESCAPE '\\' OR ulower(host) LIKE ? ESCAPE '\\')".into())
}

pub fn compile(q: &str) -> Result<Compiled, String> {
    let toks = tokenize(q.trim())?;
    let mut segs: Vec<Vec<String>> = vec![vec![]];
    for t in toks {
        if t == "|" {
            segs.push(vec![]);
        } else {
            segs.last_mut().unwrap().push(t);
        }
    }
    let mut c = Compiled { stats_limit: 100, ..Default::default() };

    // ---- search segment
    let mut groups: Vec<Vec<String>> = Vec::new(); // AND of OR-groups
    let mut negate_next = false;
    let mut join_or = false;
    let first = segs.remove(0);
    let first: Vec<String> = if first.first().map(|s| s.eq_ignore_ascii_case("search")).unwrap_or(false) {
        first[1..].to_vec()
    } else {
        first
    };
    for tok in &first {
        if tok == "NOT" {
            negate_next = true;
            continue;
        }
        if tok == "OR" {
            if groups.is_empty() || join_or {
                return Err("OR must sit between two terms".into());
            }
            join_or = true;
            continue;
        }
        if tok == "AND" {
            continue;
        }
        let mut sql = compile_term(tok, &mut c.params)?;
        if negate_next {
            sql = format!("NOT ({sql})");
            negate_next = false;
        }
        if join_or {
            groups.last_mut().unwrap().push(sql);
            join_or = false;
        } else {
            groups.push(vec![sql]);
        }
    }
    if join_or || negate_next {
        return Err("Search ends with a dangling OR/NOT".into());
    }
    c.where_sql = if groups.is_empty() {
        "1".into()
    } else {
        groups.iter().map(|g| format!("({})", g.join(" OR "))).collect::<Vec<_>>().join(" AND ")
    };

    // ---- pipes
    for seg in segs {
        let Some(cmd) = seg.first().map(|s| s.to_ascii_lowercase()) else {
            return Err("Empty pipe segment".into());
        };
        match cmd.as_str() {
            "stats" => {
                // stats count by <field>
                let lower: Vec<String> = seg.iter().map(|s| s.to_ascii_lowercase()).collect();
                if lower.get(1).map(|s| s.as_str()) != Some("count") || lower.get(2).map(|s| s.as_str()) != Some("by") {
                    return Err("Supported form: stats count by <field>".into());
                }
                let f = lower.get(3).ok_or("stats count by needs a field")?;
                if !FIELDS.contains(&f.as_str()) {
                    return Err(format!("Unknown field \"{f}\" in stats"));
                }
                c.stats_by = Some(f.clone());
            }
            "top" => {
                let f = seg.get(1).map(|s| s.to_ascii_lowercase()).ok_or("top needs a field")?;
                if !FIELDS.contains(&f.as_str()) {
                    return Err(format!("Unknown field \"{f}\" in top"));
                }
                c.stats_by = Some(f);
                c.stats_limit = 10;
            }
            "head" => {
                let n = seg.get(1).map(|s| s.parse::<usize>()).unwrap_or(Ok(10)).map_err(|_| "head needs a number")?;
                c.head = Some(n.clamp(1, 10_000));
                c.stats_limit = c.stats_limit.min(n.max(1));
            }
            "sort" => {
                let f = seg.get(1).map(|s| s.as_str()).unwrap_or("-ts");
                c.asc = match f {
                    "ts" | "+ts" | "_time" | "+_time" => true,
                    "-ts" | "-_time" => false,
                    _ => return Err("sort supports ts (oldest first) or -ts (newest first)".into()),
                };
            }
            other => return Err(format!("Unknown command \"{other}\". Supported: stats, top, head, sort")),
        }
    }
    Ok(c)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn basic() {
        let c = compile("kind=dns.query severity>=high foo").unwrap();
        assert!(c.where_sql.contains("kind = ?"));
        let u = compile("process=MÜNCHEN.exe").unwrap();
        assert!(u.where_sql.contains("ulower(process) = ?"));
        assert_eq!(u.params[0], Value::Text("münchen.exe".into()));
        assert!(c.where_sql.contains("sev >= ?"));
        assert_eq!(c.params.len(), 2 + 4);
    }
    #[test]
    fn or_binds_tighter() {
        let c = compile("a b OR c").unwrap();
        assert_eq!(c.where_sql.matches(" AND ").count(), 1);
        assert!(c.where_sql.contains(" OR (ulower(message)"));
    }
    #[test]
    fn pipes() {
        let c = compile("source=dns | stats count by domain | head 5").unwrap();
        assert_eq!(c.stats_by.as_deref(), Some("domain"));
        assert_eq!(c.head, Some(5));
    }
    #[test]
    fn errors() {
        assert!(compile("bogus=1").is_err());
        assert_eq!(compile("pd=yes").unwrap().where_sql, "(pd(domain) = 1)");
        assert_eq!(compile("vpn=yes").unwrap().where_sql, "(vpn(domain, dst_port, process) = 1)");
        assert!(compile("doman=x").unwrap_err().contains("Did you mean \"domain\""));
        assert!(compile("ip=1.2.3.4").unwrap_err().contains("src_ip"));
        assert!(compile("\"open").is_err());
        assert!(compile("x | frobnicate").is_err());
        assert!(compile("severity>=nope").is_err());
        assert!(compile("a OR OR b").is_err());
    }
    #[test]
    fn literal_percent() {
        let c = compile("50%").unwrap();
        assert_eq!(c.params[0], Value::Text("%50\\%%".into()));
    }
    #[test]
    fn wildcard_escape() {
        let mut p = vec![];
        let s = compile_term("domain=*100%_ok*", &mut p).unwrap();
        assert!(s.contains("LIKE"));
        assert_eq!(p[0], Value::Text("%100\\%\\_ok%".into()));
    }
}
