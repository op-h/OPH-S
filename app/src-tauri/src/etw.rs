//! This PC's DNS lookups via ETW (Event Tracing for Windows), provider
//! Microsoft-Windows-DNS-Client — the same source Sysmon and Portmaster-style
//! tools use. Unlike parsing `ipconfig /displaydns` it is locale-independent,
//! real-time, and tells us *which process* asked. Built on the `ferrisetw`
//! crate (adapted from its `examples/dns.rs`). Needs administrator rights;
//! without them the caller falls back to the DNS-cache poller.

#[cfg(windows)]
pub fn start(core: std::sync::Arc<crate::core::Core>) -> Result<(), String> {
    use ferrisetw::parser::Parser;
    use ferrisetw::provider::Provider;
    use ferrisetw::schema_locator::SchemaLocator;
    use ferrisetw::trace::UserTrace;
    use ferrisetw::EventRecord;
    use oph_proto::{now_ms, ProcessNames, WireEvent};
    use std::collections::HashMap;
    use std::sync::Mutex;

    const SESSION: &str = "OPH-Sentinel-DNS";
    if !core.admin {
        return Err("administrator rights required for ETW".into());
    }
    // a session left behind by a crash would make start fail
    let _ = crate::native::run_hidden("logman", &["stop", SESSION, "-ets"]);

    struct State {
        names: ProcessNames,
        seen: HashMap<(u32, String), i64>,
    }
    let state = Mutex::new(State { names: ProcessNames::new(), seen: HashMap::new() });
    let c = core.clone();
    let callback = move |record: &EventRecord, locator: &SchemaLocator| {
        // 3019 = query sent on the wire, 3010 = sent to DNS server X → Leak Check
        let id = record.event_id();
        if id == 3019 || id == 3010 {
            if let Ok(schema) = locator.event_schema(record) {
                let parser = Parser::create(record, &schema);
                if let Ok(n) = parser.try_parse::<String>("QueryName") {
                    let server = if id == 3010 { parser.try_parse::<String>("DnsServerIpAddress").ok() } else { None };
                    c.leak.on_etw(record.process_id(), &n, server);
                }
            }
            return;
        }
        // 3008 = query completed (name, type, status, results)
        if id != 3008 {
            return;
        }
        let Ok(schema) = locator.event_schema(record) else { return };
        let parser = Parser::create(record, &schema);
        let Ok(raw_name) = parser.try_parse::<String>("QueryName") else { return };
        let Some(name) = oph_proto::normalize_domain(&raw_name) else { return };
        if name.ends_with(".arpa") || name.ends_with(".local") || !name.contains('.') {
            return;
        }
        let qtype: u32 = parser.try_parse("QueryType").unwrap_or(0);
        let status: u32 = parser.try_parse("QueryStatus").unwrap_or(0);
        let results: String = parser.try_parse("QueryResults").unwrap_or_default();
        // "type:  5 cname.example;::ffff:1.2.3.4;2606:...;"
        let ips: Vec<String> = results
            .split(';')
            .map(|p| p.trim().trim_start_matches("::ffff:"))
            .filter(|p| p.parse::<std::net::IpAddr>().is_ok())
            .map(String::from)
            .take(8)
            .collect();
        {
            let mut n = c.ip_names.lock().unwrap();
            for ip in &ips {
                n.put(ip.clone(), name.clone());
            }
        }
        if !c.monitoring_on() {
            return; // paused: keep the name map fresh, record nothing
        }
        let pid = record.process_id();
        let now = now_ms();
        let process = {
            let mut st = state.lock().unwrap();
            let key = (pid, name.clone());
            if st.seen.get(&key).map(|t| now - t < 600_000).unwrap_or(false) {
                return; // same process + name within 10 min: already logged
            }
            st.seen.insert(key, now);
            if st.seen.len() > 20_000 {
                st.seen.retain(|_, t| now - *t < 600_000);
            }
            st.names.name(pid)
        };
        let mut e = WireEvent::new("dns", "dns.query", "info", format!("{process} on this-pc resolved {name}{}", if ips.is_empty() { String::new() } else { format!(" → {}", ips.join(", ")) }));
        e.host = "this-pc".into();
        e.src_ip = c.net.lock().unwrap().local_ip.clone();
        e.domain = Some(name);
        e.dst_ip = ips.first().cloned();
        e.process = Some(process);
        e.raw = serde_json::json!({"via": "etw-dns-client", "pid": pid, "qtype": qtype, "status": status});
        c.emit(e);
    };
    let provider = Provider::by_guid("1c95126e-7eea-49a9-a3fe-a378b03ddb4d").add_callback(callback).build();
    let trace = UserTrace::new().named(SESSION.to_string()).enable(provider).start_and_process().map_err(|e| format!("{e:?}"))?;
    // keep the session alive for the lifetime of the process
    Box::leak(Box::new(trace));
    Ok(())
}

#[cfg(not(windows))]
pub fn start(_core: std::sync::Arc<crate::core::Core>) -> Result<(), String> {
    Err("ETW is Windows-only".into())
}
