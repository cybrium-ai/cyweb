//! v0.8.6 — Scripted authentication for multi-step / OAuth2 / SAML.
//!
//! cyweb's `--login-user` / `--login-pass` does single-step form
//! login. That covers maybe 60% of real-world targets. The rest —
//! OAuth2 PKCE, SAML POST binding, multi-page logins, "extract bearer
//! from a JSON response" flows — needs a scriptable runtime.
//!
//! This module loads a YAML auth script:
//!
//! ```yaml
//! name: "Acme OAuth2 PKCE"
//! steps:
//!   - name: get-login-page
//!     method: GET
//!     url: "https://idp.acme.com/oauth2/authorize?client_id={{client_id}}&..."
//!     extract:
//!       csrf: 'name="_csrf" value="([^"]+)"'
//!
//!   - name: post-credentials
//!     method: POST
//!     url: "https://idp.acme.com/login"
//!     body: "username={{user}}&password={{pass}}&_csrf={{csrf}}"
//!     follow_redirects: false
//!     extract:
//!       auth_code: 'location: .*[?&]code=([^&]+)'
//!
//!   - name: exchange-code
//!     method: POST
//!     url: "https://api.acme.com/oauth2/token"
//!     body: "grant_type=authorization_code&code={{auth_code}}"
//!     extract:
//!       access_token: '"access_token":"([^"]+)"'
//!
//! apply:
//!   headers:
//!     Authorization: "Bearer {{access_token}}"
//! ```
//!
//! Each step issues an HTTP request, optionally extracts values via
//! regex capture groups (matched against headers + body + status),
//! and stores them in a shared variable map. Subsequent steps
//! reference the captured values via `{{name}}` placeholders.
//!
//! Variables `user` and `pass` are pre-populated from
//! `--login-user`/`--login-pass` (or `CYWEB_AUTH_USER` /
//! `CYWEB_AUTH_PASS` env). Every other variable comes from a
//! step's `extract:` block.
//!
//! Special helper variables are auto-injected before the first step:
//!  - `pkce_verifier`  — 96-character random URL-safe string
//!  - `pkce_challenge` — base64url(sha256(pkce_verifier))
//!  - `nonce`          — 32-char random hex
//!  - `state`          — 32-char random hex

use base64::Engine;
use rand::Rng;
use regex::Regex;
use reqwest::{Method, Client};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Deserialize, Clone)]
pub struct AuthScript {
    #[serde(default)]
    pub name: String,
    pub steps: Vec<AuthStep>,
    #[serde(default)]
    pub apply: ApplyConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthStep {
    #[serde(default)]
    pub name: String,
    #[serde(default = "default_method")]
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub body: String,
    #[serde(default = "default_true")]
    pub follow_redirects: bool,
    /// Map of `var_name -> regex`. Each regex is matched against
    /// the response (status / headers / body in that order); first
    /// capture group becomes the variable's value.
    #[serde(default)]
    pub extract: HashMap<String, String>,
    /// Per-step timeout (seconds). Default 15.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
}

fn default_method() -> String { "GET".into() }
fn default_true() -> bool { true }
fn default_timeout() -> u64 { 15 }

/// Outputs to attach to every subsequent scan request.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct ApplyConfig {
    /// Headers to attach (e.g., Authorization: Bearer {{access_token}}).
    /// Templated against the variable map.
    #[serde(default)]
    pub headers: HashMap<String, String>,
    /// Cookies to attach (Cookie header). Templated.
    #[serde(default)]
    pub cookies: HashMap<String, String>,
}

#[derive(Debug)]
pub struct AuthArtifacts {
    /// Concrete header values (already templated). The scanner
    /// attaches these as default headers.
    pub headers: Vec<(String, String)>,
    /// Cookie string already formatted as "k=v; k=v".
    pub cookies: String,
    /// Full variable snapshot — useful for debugging / re-login.
    pub vars: HashMap<String, String>,
}

#[derive(Debug)]
pub struct AuthError {
    pub step: String,
    pub message: String,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "auth-script error in step `{}`: {}", self.step, self.message)
    }
}

impl std::error::Error for AuthError {}

/// Load + parse a YAML script from disk.
pub fn load(path: &str) -> Result<AuthScript, String> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {}", path, e))?;
    serde_yaml::from_str::<AuthScript>(&raw)
        .map_err(|e| format!("failed to parse {}: {}", path, e))
}

/// Execute the script. `seed_user` / `seed_pass` are optional —
/// when supplied they pre-populate `{{user}}` and `{{pass}}` so
/// scripts can reference credentials without leaking them inside
/// the YAML.
pub async fn run(
    client: &Client,
    script: &AuthScript,
    seed_user: Option<&str>,
    seed_pass: Option<&str>,
) -> Result<AuthArtifacts, AuthError> {
    let mut vars: HashMap<String, String> = HashMap::new();
    if let Some(u) = seed_user { vars.insert("user".into(), u.into()); }
    if let Some(p) = seed_pass { vars.insert("pass".into(), p.into()); }
    inject_helpers(&mut vars);

    let mut cookies: Vec<(String, String)> = Vec::new();

    for step in &script.steps {
        let url = resolve_vars(&step.url, &vars);
        let method = match step.method.to_uppercase().as_str() {
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            "PATCH" => Method::PATCH,
            "HEAD" => Method::HEAD,
            "OPTIONS" => Method::OPTIONS,
            _ => Method::GET,
        };

        // We follow redirects per-step via the client config — but
        // OAuth flows often need the 302 surface so the script can
        // extract the `code=` parameter from the Location header.
        // When `follow_redirects: false`, we issue the request via a
        // one-shot client that doesn't follow.
        let step_client = if step.follow_redirects {
            client.clone()
        } else {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(step.timeout_secs))
                .danger_accept_invalid_certs(true)
                .build()
                .map_err(|e| AuthError {
                    step: step.name.clone(),
                    message: format!("client build: {}", e),
                })?
        };

        let mut req = step_client.request(method, &url);
        for (k, v) in &step.headers {
            req = req.header(k.as_str(), resolve_vars(v, &vars).as_str());
        }
        // Auto-attach any cookies we've captured from prior steps
        if !cookies.is_empty() {
            let cookie_str = cookies.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("; ");
            req = req.header("Cookie", cookie_str);
        }
        if !step.body.is_empty() {
            let body = resolve_vars(&step.body, &vars);
            // If the body looks form-encoded and Content-Type wasn't
            // set explicitly, default it.
            if !step.headers.keys().any(|k| k.eq_ignore_ascii_case("content-type")) {
                if body.contains('=') && !body.starts_with('{') {
                    req = req.header("Content-Type", "application/x-www-form-urlencoded");
                } else if body.starts_with('{') {
                    req = req.header("Content-Type", "application/json");
                }
            }
            req = req.body(body);
        }

        let resp = req.send().await.map_err(|e| AuthError {
            step: step.name.clone(),
            message: format!("send: {}", e),
        })?;

        let status = resp.status();
        let mut header_dump = String::new();
        for (k, v) in resp.headers().iter() {
            header_dump.push_str(&format!("{}: {}\n", k, v.to_str().unwrap_or("")));
        }
        // Capture Set-Cookie values for the next step
        for v in resp.headers().get_all("set-cookie").iter() {
            if let Ok(sv) = v.to_str() {
                if let Some((nv, _)) = sv.split_once(';') {
                    if let Some((n, v)) = nv.split_once('=') {
                        cookies.push((n.trim().into(), v.trim().into()));
                    }
                }
            }
        }
        let body = resp.text().await.unwrap_or_default();

        // Run extractors. We search the concatenated
        // status-headers-body string so a regex like
        // `location: .*code=(...)` works against the headers block.
        let haystack = format!("HTTP {}\n{}\n{}", status.as_u16(), header_dump, body);
        for (var, pattern) in &step.extract {
            let re = Regex::new(pattern).map_err(|e| AuthError {
                step: step.name.clone(),
                message: format!("invalid regex `{}`: {}", pattern, e),
            })?;
            if let Some(caps) = re.captures(&haystack) {
                if let Some(m) = caps.get(1) {
                    vars.insert(var.clone(), m.as_str().to_string());
                } else if let Some(m) = caps.get(0) {
                    vars.insert(var.clone(), m.as_str().to_string());
                }
            }
            // No match = leave var unset; subsequent steps can detect
            // and choose to fail or fall through.
        }
    }

    // Resolve apply.headers / apply.cookies against final vars
    let headers: Vec<(String, String)> = script.apply.headers.iter()
        .map(|(k, v)| (k.clone(), resolve_vars(v, &vars)))
        .collect();
    let cookie_pairs: Vec<String> = script.apply.cookies.iter()
        .map(|(k, v)| format!("{}={}", k, resolve_vars(v, &vars)))
        .collect();
    // Union with cookies captured from Set-Cookie during the script
    let captured = cookies.iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>();
    let all_cookies = [cookie_pairs, captured].concat().join("; ");

    Ok(AuthArtifacts {
        headers,
        cookies: all_cookies,
        vars,
    })
}

/// Substitute `{{name}}` placeholders. Identical semantics to
/// templates.rs::resolve_vars, but we keep a separate copy here to
/// avoid a circular dependency.
fn resolve_vars(template: &str, vars: &HashMap<String, String>) -> String {
    let mut result = template.to_string();
    for (key, value) in vars {
        result = result.replace(&format!("{{{{{}}}}}", key), value);
    }
    result
}

/// Inject helper variables (PKCE, nonce, state) before the first
/// step runs. PKCE is the OAuth2 standard for public clients —
/// upstream RFC 7636.
fn inject_helpers(vars: &mut HashMap<String, String>) {
    // 96-char URL-safe random for PKCE verifier (43-128 chars per RFC)
    let mut rng = rand::thread_rng();
    let verifier: String = (0..96)
        .map(|_| {
            const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
            CHARS[rng.gen_range(0..CHARS.len())] as char
        })
        .collect();
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    vars.entry("pkce_verifier".into()).or_insert(verifier);
    vars.entry("pkce_challenge".into()).or_insert(challenge);

    let nonce: String = (0..32).map(|_| {
        const HEX: &[u8] = b"0123456789abcdef";
        HEX[rng.gen_range(0..HEX.len())] as char
    }).collect();
    let state: String = (0..32).map(|_| {
        const HEX: &[u8] = b"0123456789abcdef";
        HEX[rng.gen_range(0..HEX.len())] as char
    }).collect();
    vars.entry("nonce".into()).or_insert(nonce);
    vars.entry("state".into()).or_insert(state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_script() {
        let yaml = r#"
name: simple
steps:
  - name: login
    method: POST
    url: https://idp/login
    body: "u={{user}}&p={{pass}}"
"#;
        let s: AuthScript = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(s.name, "simple");
        assert_eq!(s.steps.len(), 1);
        assert_eq!(s.steps[0].method, "POST");
        assert!(s.steps[0].follow_redirects); // default
    }

    #[test]
    fn resolve_vars_substitutes_placeholders() {
        let mut v = HashMap::new();
        v.insert("user".into(), "alice".into());
        v.insert("pass".into(), "secret".into());
        assert_eq!(
            resolve_vars("u={{user}}&p={{pass}}", &v),
            "u=alice&p=secret",
        );
    }

    #[test]
    fn resolve_vars_leaves_unknown_placeholders() {
        let v = HashMap::new();
        assert_eq!(
            resolve_vars("Hello {{x}}!", &v),
            "Hello {{x}}!",
        );
    }

    #[test]
    fn inject_helpers_populates_pkce_pair() {
        let mut v = HashMap::new();
        inject_helpers(&mut v);
        assert!(v.contains_key("pkce_verifier"));
        assert!(v.contains_key("pkce_challenge"));
        assert_eq!(v["pkce_verifier"].len(), 96);
        // base64url(sha256(...)) is always 43 chars without padding
        assert_eq!(v["pkce_challenge"].len(), 43);
        // PKCE pair must be deterministic: re-derive challenge from
        // verifier and compare.
        let derived = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(v["pkce_verifier"].as_bytes()));
        assert_eq!(derived, v["pkce_challenge"]);
    }

    #[test]
    fn inject_helpers_does_not_overwrite_user_vars() {
        let mut v = HashMap::new();
        v.insert("nonce".into(), "user-controlled".into());
        inject_helpers(&mut v);
        assert_eq!(v["nonce"], "user-controlled");
    }

    #[test]
    fn inject_helpers_nonce_state_are_hex() {
        let mut v = HashMap::new();
        inject_helpers(&mut v);
        assert_eq!(v["nonce"].len(), 32);
        assert_eq!(v["state"].len(), 32);
        assert!(v["nonce"].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(v["state"].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn shipped_examples_all_parse() {
        // Each example in examples/auth/ must parse + have at least
        // one step. Acts as a lint preventing example rot.
        let examples = [
            "examples/auth/form-multi-step.yaml",
            "examples/auth/oauth-pkce.yaml",
            "examples/auth/saml-post.yaml",
            "examples/auth/bearer-from-json.yaml",
        ];
        for path in examples {
            let s = load(path).unwrap_or_else(|e| panic!("{}: {}", path, e));
            assert!(!s.steps.is_empty(), "{} has no steps", path);
            // Every step's URL must either start with http(s):// OR
            // be a {{var}} placeholder that an earlier step is
            // expected to populate (legitimate for chained flows
            // where step N+1's URL comes from step N's response).
            for step in &s.steps {
                let u = step.url.trim();
                let ok = u.starts_with("http")
                    || (u.starts_with("{{") && u.ends_with("}}"));
                assert!(ok, "{}: bad url `{}`", path, u);
            }
        }
    }

    #[test]
    fn parses_full_oauth_script() {
        let yaml = r#"
name: "OAuth2 PKCE"
steps:
  - name: authorize
    method: GET
    url: "https://idp/authorize?challenge={{pkce_challenge}}"
    extract:
      csrf: 'name="_csrf" value="([^"]+)"'
  - name: login
    method: POST
    url: "https://idp/login"
    body: "u={{user}}&p={{pass}}&_csrf={{csrf}}"
    follow_redirects: false
    extract:
      code: 'location: .*[?&]code=([^&]+)'
  - name: exchange
    method: POST
    url: "https://idp/token"
    body: 'grant_type=authorization_code&code={{code}}&verifier={{pkce_verifier}}'
    extract:
      access_token: '"access_token":"([^"]+)"'
apply:
  headers:
    Authorization: "Bearer {{access_token}}"
"#;
        let s: AuthScript = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(s.steps.len(), 3);
        assert_eq!(s.steps[1].follow_redirects, false);
        assert!(s.apply.headers.contains_key("Authorization"));
    }
}
