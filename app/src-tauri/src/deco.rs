//! TP-Link Deco local API client (login, DHCP DNS, address reservation, logout).
//!
//! TP-Link publishes no API for Deco. This is a Rust port of the protocol as
//! implemented by the open-source projects amosyuen/ha-tplink-deco (Home
//! Assistant), AlexandrErohin/TP-Link-Archer-C6U (tplinkrouterc6u) and
//! roquerodrigo/tplink-deco-api:
//!   1. `login?form=keys` → RSA password key, `login?form=auth` → RSA signing key + seq
//!   2. every request body is AES-128-CBC/PKCS7 (random 16-digit key + IV), base64,
//!      plus `sign` = RSA-PKCS#1v1.5("k=<key>&i=<iv>&h=md5(admin+pw)&s=<seq+len>")
//!   3. `login?form=login` returns `stok` (in the URL) and a `sysauth` cookie.
//!
//! Address reservation writes are confirmed on real hardware by those projects;
//! the DHCP DNS form (`admin/dhcp?form=dhcp_info`) is documented but unproven, so
//! callers always read first and verify after writing.

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use base64::Engine;
use md5::{Digest, Md5};
use rand::Rng;
use rsa::BigUint;
use serde_json::{json, Value};
use std::time::Duration;

type Enc = cbc::Encryptor<aes::Aes128>;
type Dec = cbc::Decryptor<aes::Aes128>;
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

struct RsaKey {
    n: BigUint,
    e: BigUint,
}

pub struct Deco {
    base: String,
    agent: ureq::Agent,
    key: String,
    iv: String,
    hash: String,
    seq: u64,
    sign: RsaKey,
    stok: String,
    cookie: String,
}

#[derive(Debug)]
pub enum DecoError {
    Unreachable(String),
    WrongPassword(Option<i64>),
    OtherSession,
    Unsupported(String),
    Api(String),
}

impl std::fmt::Display for DecoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecoError::Unreachable(e) => write!(f, "Could not reach the Deco: {e}"),
            DecoError::WrongPassword(Some(n)) => write!(f, "Wrong Deco password ({n} attempts left before the Deco locks login for a while)"),
            DecoError::WrongPassword(None) => write!(f, "Wrong Deco password. Use the owner password of your TP-Link ID / Deco app (manager accounts cannot log in locally)"),
            DecoError::OtherSession => write!(f, "The Deco refused the login because another admin session is active. Close the Deco app on your phone and try again"),
            DecoError::Unsupported(w) => write!(f, "This Deco firmware does not allow {w} from the local network. Use the Deco app steps instead"),
            DecoError::Api(e) => write!(f, "Deco error: {e}"),
        }
    }
}

fn hex_big(h: &str) -> Option<BigUint> {
    BigUint::parse_bytes(h.trim().as_bytes(), 16)
}

/// RSA PKCS#1 v1.5 type-2 encryption, block by block, hex output (as the Deco web UI does).
fn rsa_encrypt(key: &RsaKey, plain: &[u8]) -> String {
    let k = (key.n.bits() + 7) / 8;
    let per = k - 11;
    let mut rng = rand::thread_rng();
    let mut out = String::new();
    for block in plain.chunks(per) {
        let mut em = Vec::with_capacity(k);
        em.extend_from_slice(&[0, 2]);
        while em.len() < k - block.len() - 1 {
            let b: u8 = rng.gen();
            if b != 0 {
                em.push(b);
            }
        }
        em.push(0);
        em.extend_from_slice(block);
        let c = BigUint::from_bytes_be(&em).modpow(&key.e, &key.n);
        out.push_str(&format!("{:0width$x}", c, width = k * 2));
    }
    out
}

fn digits16() -> String {
    let mut rng = rand::thread_rng();
    format!("{}", rng.gen_range(1_000_000_000_000_000u64..=9_999_999_999_999_999u64))
}

fn url_enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            b' ' => "+".into(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

impl Deco {
    fn post(&self, path: &str, body: &str) -> Result<(Value, Option<String>), DecoError> {
        let url = format!("{}/cgi-bin/luci/;stok={}/{}", self.base, self.stok, path);
        let mut req = self.agent.post(&url).set("Content-Type", "application/json").set("Accept", "application/json");
        if !self.cookie.is_empty() {
            req = req.set("Cookie", &self.cookie);
        }
        let resp = match req.send_string(body) {
            Ok(r) => r,
            Err(ureq::Error::Status(403, _)) => return Err(DecoError::OtherSession),
            Err(ureq::Error::Status(401, _)) | Err(ureq::Error::Status(404, _)) => {
                return Err(DecoError::Unsupported("this request (endpoint missing on this model)".into()))
            }
            Err(e) => return Err(DecoError::Unreachable(e.to_string())),
        };
        let cookie = resp.all("Set-Cookie").iter().find_map(|c| {
            let i = c.find("sysauth=")?;
            let v: String = c[i + 8..].chars().take_while(|ch| ch.is_ascii_hexdigit()).collect();
            (!v.is_empty()).then(|| format!("sysauth={v}"))
        });
        let text = resp.into_string().map_err(|e| DecoError::Unreachable(e.to_string()))?;
        let v: Value = serde_json::from_str(&text).map_err(|_| DecoError::Api("unexpected (non-JSON) answer".into()))?;
        Ok((v, cookie))
    }

    fn encrypt(&self, payload: &Value) -> String {
        let plain = serde_json::to_string(payload).unwrap();
        let ct = Enc::new(self.key.as_bytes().into(), self.iv.as_bytes().into()).encrypt_padded_vec_mut::<Pkcs7>(plain.as_bytes());
        B64.encode(ct)
    }

    fn decrypt(&self, b64: &str) -> Option<Value> {
        let ct = B64.decode(b64.trim()).ok()?;
        let pt = Dec::new(self.key.as_bytes().into(), self.iv.as_bytes().into()).decrypt_padded_vec_mut::<Pkcs7>(&ct).ok()?;
        serde_json::from_slice(&pt).ok()
    }

    /// Encrypted request; returns the decrypted envelope (with error_code checked).
    fn call(&mut self, path: &str, payload: Value) -> Result<Value, DecoError> {
        let data = self.encrypt(&payload);
        let sign_text = format!("k={}&i={}&h={}&s={}", self.key, self.iv, self.hash, self.seq + data.len() as u64);
        let body = format!("sign={}&data={}", rsa_encrypt(&self.sign, sign_text.as_bytes()), url_enc(&data));
        let (raw, cookie) = self.post(path, &body)?;
        if let Some(c) = cookie {
            self.cookie = c;
        }
        let env = match raw.get("data").and_then(|d| d.as_str()) {
            Some(d) if !d.is_empty() => self.decrypt(d).ok_or_else(|| DecoError::Api("could not decrypt the answer".into()))?,
            _ => raw,
        };
        let code = env.get("error_code").or_else(|| env.get("errorcode")).cloned().unwrap_or(json!(0));
        let ok = code == json!(0) || code == json!("0") || code.is_null();
        if !ok {
            if code == json!(-5002) && path.starts_with("login") {
                let left = env.pointer("/result/attemptsAllowed").and_then(|v| v.as_i64());
                return Err(DecoError::WrongPassword(left));
            }
            return Err(DecoError::Api(format!("error_code {code} on {path}")));
        }
        Ok(env)
    }

    /// Log in with the owner password. `host` is the gateway IP (e.g. 192.168.68.1).
    pub fn login(host: &str, password: &str) -> Result<Deco, DecoError> {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(8))
            .redirects(0)
            .tls_config(crate::router::insecure_tls()) // Deco uses a self-signed certificate
            .build();
        let mut d = Deco {
            base: format!("https://{host}"),
            agent,
            key: digits16(),
            iv: digits16(),
            hash: format!("{:x}", Md5::digest(format!("admin{password}").as_bytes())),
            seq: 0,
            sign: RsaKey { n: BigUint::from(1u8), e: BigUint::from(1u8) },
            stok: String::new(),
            cookie: String::new(),
        };
        let read = r#"{"operation":"read"}"#;
        let (keys, _) = d.post("login?form=keys", read)?;
        let pw = keys.pointer("/result/password").and_then(|v| v.as_array()).ok_or_else(|| DecoError::Unsupported("local login".into()))?;
        let pw_key = RsaKey {
            n: pw.first().and_then(|v| v.as_str()).and_then(hex_big).ok_or_else(|| DecoError::Api("bad password key".into()))?,
            e: pw.get(1).and_then(|v| v.as_str()).and_then(hex_big).ok_or_else(|| DecoError::Api("bad password key".into()))?,
        };
        let (auth, _) = d.post("login?form=auth", read)?;
        let k = auth.pointer("/result/key").and_then(|v| v.as_array()).ok_or_else(|| DecoError::Api("no signing key".into()))?;
        d.sign = RsaKey {
            n: k.first().and_then(|v| v.as_str()).and_then(hex_big).ok_or_else(|| DecoError::Api("bad signing key".into()))?,
            e: k.get(1).and_then(|v| v.as_str()).and_then(hex_big).ok_or_else(|| DecoError::Api("bad signing key".into()))?,
        };
        d.seq = auth.pointer("/result/seq").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).unwrap_or(0);
        let enc_pw = rsa_encrypt(&pw_key, password.as_bytes());
        let env = d.call("login?form=login", json!({"params": {"password": enc_pw}, "operation": "login"}))?;
        d.stok = env.pointer("/result/stok").and_then(|v| v.as_str()).ok_or(DecoError::WrongPassword(None))?.to_string();
        if d.cookie.is_empty() {
            return Err(DecoError::Api("login answered without a session cookie".into()));
        }
        Ok(d)
    }

    pub fn dhcp_read(&mut self) -> Result<Value, DecoError> {
        let env = self.call("admin/dhcp?form=dhcp_info", json!({"operation": "read"})).map_err(|e| match e {
            DecoError::Api(_) | DecoError::Unsupported(_) => DecoError::Unsupported("reading the DHCP/DNS settings".into()),
            other => other,
        })?;
        env.get("result").cloned().filter(|r| r.get("primaryDns").is_some() || r.get("startIpAddress").is_some()).ok_or_else(|| DecoError::Unsupported("reading the DHCP/DNS settings".into()))
    }

    /// Write DNS while keeping every other DHCP field exactly as read.
    pub fn dhcp_set_dns(&mut self, current: &Value, primary: &str, secondary: &str) -> Result<(), DecoError> {
        let mut params = current.clone();
        params["primaryDns"] = json!(primary);
        params["secondaryDns"] = json!(secondary);
        self.call("admin/dhcp?form=dhcp_info", json!({"operation": "write", "params": params})).map(|_| ()).map_err(|e| match e {
            DecoError::Api(m) => DecoError::Unsupported(format!("changing DNS ({m})")),
            other => other,
        })
    }

    pub fn reservations(&mut self) -> Result<Vec<(String, String)>, DecoError> {
        let env = self.call("admin/client?form=addr_reservation", json!({"operation": "getlist"}))?;
        let list = env.pointer("/result/reservation_list").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        Ok(list
            .iter()
            .filter_map(|r| Some((r.get("mac")?.as_str()?.to_ascii_uppercase(), r.get("ip")?.as_str()?.to_string())))
            .collect())
    }

    /// (MAC "AA-BB-..", device name) from the Deco's client list — the names shown in the Deco app.
    pub fn client_names(&mut self) -> Result<Vec<(String, String)>, DecoError> {
        let env = self.call("admin/client?form=client_list", json!({"operation": "read", "params": {"device_mac": "default"}}))?;
        let list = env.pointer("/result/client_list").and_then(|v| v.as_array()).cloned().unwrap_or_default();
        Ok(list
            .iter()
            .filter_map(|c| {
                let mac = c.get("mac")?.as_str()?.to_ascii_uppercase();
                let raw = c.get("name")?.as_str()?;
                let name = B64.decode(raw).ok().and_then(|b| String::from_utf8(b).ok()).unwrap_or_else(|| raw.to_string());
                let name: String = name.chars().filter(|ch| !ch.is_control()).take(64).collect();
                (!name.trim().is_empty()).then_some((mac, name))
            })
            .collect())
    }

    pub fn reserve(&mut self, mac: &str, ip: &str) -> Result<(), DecoError> {
        self.call("admin/client?form=addr_reservation", json!({"operation": "add", "params": {"reservation_list": [{"mac": mac, "ip": ip}]}})).map(|_| ())
    }

    pub fn logout(mut self) {
        let _ = self.call("admin/system?form=logout", json!({"operation": "logout"}));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rsa_block_layout() {
        // 512-bit style modulus: k = 64 bytes, 53 plaintext bytes per block, hex = 128 chars per block
        let n = BigUint::parse_bytes(b"c3a1f7e5b9d2c4a6e8f0b1d3c5e7f9a1b3d5e7f9a1c3e5f7b9d1c3e5a7f9b1d3c5e7f9a1b3d5e7f9a1c3e5f7b9d1c3e5a7f9b1d3c5e7f9a1b3d5e7f9a1c3e5f7", 16).unwrap();
        let key = RsaKey { n, e: BigUint::from(65537u32) };
        assert_eq!(rsa_encrypt(&key, &[b'a'; 53]).len(), 128);
        assert_eq!(rsa_encrypt(&key, &[b'a'; 54]).len(), 256);
    }
    #[test]
    fn aes_roundtrip_and_key_shape() {
        let k = digits16();
        assert_eq!(k.len(), 16);
        assert!(!k.starts_with('0'));
        let d = Deco {
            base: String::new(),
            agent: ureq::agent(),
            key: "1234567890123456".into(),
            iv: "6543210987654321".into(),
            hash: String::new(),
            seq: 0,
            sign: RsaKey { n: BigUint::from(1u8), e: BigUint::from(1u8) },
            stok: String::new(),
            cookie: String::new(),
        };
        let v = json!({"operation": "read", "params": {"x": "é"}});
        assert_eq!(d.decrypt(&d.encrypt(&v)).unwrap(), v);
        assert_eq!(url_enc("a+b/="), "a%2Bb%2F%3D");
    }
}
