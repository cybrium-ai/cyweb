//! Third-party template converter — imports the common external
//! "scan template" YAML schema into cyweb's own template format.
//!
//! Usage:
//!   cyweb convert-templates --input /path/to/templates --output ~/.cyweb/templates/
//!
//! The expected source schema is the broad community standard:
//! `id` + `info` block + `http` (or `requests`) block with
//! `matchers` / `extractors` / `headers` etc. HTTP templates are
//! converted; non-HTTP variants (DNS, TCP, SSL, headless) are
//! skipped with a warning.

use std::path::Path;

/// Convert a directory of third-party templates to cyweb format.
pub fn convert_directory(input_dir: &str, output_dir: &str) -> ConvertResult {
    let input = Path::new(input_dir);
    let output = Path::new(output_dir);

    if !input.exists() {
        return ConvertResult {
            total: 0, converted: 0, skipped: 0, errors: 0,
            error_details: vec!["Input directory does not exist".into()],
        };
    }

    std::fs::create_dir_all(output).ok();

    let mut result = ConvertResult::default();
    let files = walkdir(input);

    for path in &files {
        if !path.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
            continue;
        }

        result.total += 1;

        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                result.errors += 1;
                result.error_details.push(format!("{}: {}", path.display(), e));
                continue;
            }
        };

        match convert_single(&content) {
            Ok(converted) => {
                // Preserve directory structure
                let rel_path = path.strip_prefix(input).unwrap_or(path);
                let out_path = output.join(rel_path);
                if let Some(parent) = out_path.parent() {
                    std::fs::create_dir_all(parent).ok();
                }
                match std::fs::write(&out_path, converted) {
                    Ok(_) => result.converted += 1,
                    Err(e) => {
                        result.errors += 1;
                        result.error_details.push(format!("Write {}: {}", out_path.display(), e));
                    }
                }
            }
            Err(reason) => {
                result.skipped += 1;
                if result.error_details.len() < 20 {
                    result.error_details.push(format!("{}: {}", path.display(), reason));
                }
            }
        }
    }

    result
}

#[derive(Debug, Default)]
pub struct ConvertResult {
    pub total: usize,
    pub converted: usize,
    pub skipped: usize,
    pub errors: usize,
    pub error_details: Vec<String>,
}

/// Convert a single template YAML string to cyweb format.
fn convert_single(src_yaml: &str) -> Result<String, String> {
    let tmpl: serde_yaml::Value = serde_yaml::from_str(src_yaml)
        .map_err(|e| format!("YAML parse error: {}", e))?;

    let id = tmpl.get("id")
        .and_then(|v| v.as_str())
        .ok_or("Missing id field")?;

    let info = tmpl.get("info")
        .ok_or("Missing info block")?;

    // Only convert HTTP templates
    let http = tmpl.get("http")
        .or_else(|| tmpl.get("requests"))
        .ok_or("Not an HTTP template (DNS/TCP/headless not supported yet)")?;

    let requests_arr = http.as_sequence()
        .ok_or("http/requests is not a list")?;

    // Build cyweb template
    let mut output = serde_yaml::Mapping::new();

    // id — namespace under cyweb-tmpl- to identify converted entries
    output.insert(
        serde_yaml::Value::String("id".into()),
        serde_yaml::Value::String(format!("cyweb-tmpl-{}", id)),
    );

    // info block
    let mut info_out = serde_yaml::Mapping::new();
    info_out.insert(
        serde_yaml::Value::String("name".into()),
        info.get("name").cloned().unwrap_or(serde_yaml::Value::String(id.to_string())),
    );
    info_out.insert(
        serde_yaml::Value::String("severity".into()),
        info.get("severity").cloned().unwrap_or(serde_yaml::Value::String("info".into())),
    );
    if let Some(desc) = info.get("description") {
        info_out.insert(serde_yaml::Value::String("description".into()), desc.clone());
    }
    if let Some(tags) = info.get("tags") {
        let tags_str = tags.as_str().unwrap_or("");
        let tags_vec: Vec<serde_yaml::Value> = tags_str
            .split(',')
            .map(|t| serde_yaml::Value::String(t.trim().to_string()))
            .collect();
        info_out.insert(serde_yaml::Value::String("tags".into()), serde_yaml::Value::Sequence(tags_vec));
    }
    if let Some(refs) = info.get("reference") {
        info_out.insert(serde_yaml::Value::String("reference".into()), refs.clone());
    }
    if let Some(remediation) = info.get("remediation") {
        info_out.insert(serde_yaml::Value::String("remediation".into()), remediation.clone());
    }

    // Classification → CWE
    if let Some(classification) = info.get("classification") {
        if let Some(cwe_id) = classification.get("cwe-id") {
            let cwe_vec = match cwe_id {
                serde_yaml::Value::Sequence(seq) => seq.clone(),
                serde_yaml::Value::String(s) => vec![serde_yaml::Value::String(s.clone())],
                serde_yaml::Value::Number(n) => vec![serde_yaml::Value::String(format!("CWE-{}", n.as_u64().unwrap_or(0)))],
                _ => vec![],
            };
            if !cwe_vec.is_empty() {
                info_out.insert(serde_yaml::Value::String("cwe".into()), serde_yaml::Value::Sequence(cwe_vec));
            }
        }
    }

    output.insert(serde_yaml::Value::String("info".into()), serde_yaml::Value::Mapping(info_out));

    // Convert request steps
    let mut steps = Vec::new();
    for req in requests_arr {
        let step = convert_request_step(req)?;
        steps.push(step);
    }
    output.insert(serde_yaml::Value::String("requests".into()), serde_yaml::Value::Sequence(steps));

    serde_yaml::to_string(&serde_yaml::Value::Mapping(output))
        .map_err(|e| format!("Serialization error: {}", e))
}

fn convert_request_step(req: &serde_yaml::Value) -> Result<serde_yaml::Value, String> {
    let mut step = serde_yaml::Mapping::new();

    // v0.8.3 — Raw HTTP request format. Templates with a `raw:` block
    // ship the full HTTP wire format as a literal block scalar:
    //
    //   raw:
    //     - |
    //       POST /api/login HTTP/1.1
    //       Host: {{Hostname}}
    //       Content-Type: application/x-www-form-urlencoded
    //
    //       username=admin&password=admin
    //
    // We parse each entry into structured method / path / headers /
    // body and combine into a step. Multiple raw entries become
    // multiple paths (one per request line).
    if let Some(raw) = req.get("raw") {
        if let Some(raw_seq) = raw.as_sequence() {
            let parsed: Vec<RawHttp> = raw_seq.iter()
                .filter_map(|v| v.as_str())
                .filter_map(parse_raw_http)
                .collect();

            if !parsed.is_empty() {
                // Method, path, body, headers from the FIRST parsed
                // raw block (most templates have just one). All
                // request-line + header fields collapse into the
                // structured step. Subsequent raw entries become
                // alternate paths under the same method.
                step.insert(
                    serde_yaml::Value::String("method".into()),
                    serde_yaml::Value::String(parsed[0].method.clone()),
                );

                let paths: Vec<serde_yaml::Value> = parsed.iter()
                    .map(|r| serde_yaml::Value::String(r.path.clone()))
                    .collect();
                step.insert(
                    serde_yaml::Value::String("path".into()),
                    serde_yaml::Value::Sequence(paths),
                );

                if !parsed[0].body.is_empty() {
                    step.insert(
                        serde_yaml::Value::String("body".into()),
                        serde_yaml::Value::String(parsed[0].body.clone()),
                    );
                }

                if !parsed[0].headers.is_empty() {
                    let mut h_map = serde_yaml::Mapping::new();
                    for (k, v) in &parsed[0].headers {
                        h_map.insert(
                            serde_yaml::Value::String(k.clone()),
                            serde_yaml::Value::String(v.clone()),
                        );
                    }
                    step.insert(
                        serde_yaml::Value::String("headers".into()),
                        serde_yaml::Value::Mapping(h_map),
                    );
                }
                // Fall through so matchers / extractors / etc. still
                // get copied below.
            }
        }
    }

    // Method (only set if raw didn't already)
    if !step.contains_key(serde_yaml::Value::String("method".into())) {
        if let Some(method) = req.get("method") {
            step.insert(serde_yaml::Value::String("method".into()), method.clone());
        }
    }

    // Path (only set if raw didn't already)
    if !step.contains_key(serde_yaml::Value::String("path".into())) {
        if let Some(path) = req.get("path") {
            step.insert(serde_yaml::Value::String("path".into()), path.clone());
        }
    }

    // Body (only set if raw didn't already)
    if !step.contains_key(serde_yaml::Value::String("body".into())) {
        if let Some(body) = req.get("body") {
            step.insert(serde_yaml::Value::String("body".into()), body.clone());
        }
    }

    // Headers (only set if raw didn't already)
    if !step.contains_key(serde_yaml::Value::String("headers".into())) {
        if let Some(headers) = req.get("headers") {
            step.insert(serde_yaml::Value::String("headers".into()), headers.clone());
        }
    }

    // Matchers — pass through (format is compatible)
    if let Some(matchers) = req.get("matchers") {
        step.insert(serde_yaml::Value::String("matchers".into()), matchers.clone());
    }

    // Matchers condition
    if let Some(cond) = req.get("matchers-condition") {
        step.insert(serde_yaml::Value::String("matchers_condition".into()), cond.clone());
    }

    // Extractors — pass through
    if let Some(extractors) = req.get("extractors") {
        step.insert(serde_yaml::Value::String("extractors".into()), extractors.clone());
    }

    // Redirects
    if let Some(redirects) = req.get("redirects") {
        step.insert(serde_yaml::Value::String("redirects".into()), redirects.clone());
    }
    if let Some(max) = req.get("max-redirects") {
        step.insert(serde_yaml::Value::String("max_redirects".into()), max.clone());
    }

    // Cookie reuse
    if let Some(cr) = req.get("cookie-reuse") {
        step.insert(serde_yaml::Value::String("cookie_reuse".into()), cr.clone());
    }

    Ok(serde_yaml::Value::Mapping(step))
}

/// Parsed raw-HTTP request. Method / path come from the request line;
/// headers and body from the rest. Variable placeholders like
/// `{{Hostname}}` and `{{BaseURL}}` are preserved verbatim — cyweb's
/// runtime expansion handles them at scan time.
#[derive(Debug, Default)]
struct RawHttp {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

/// Parse a raw HTTP/1.x request block into structured fields.
/// Returns None on malformed input; caller falls back to other
/// fields in the step.
pub(crate) fn parse_raw_http(raw: &str) -> Option<RawHttp> {
    let raw = raw.trim_start_matches('\n');
    // Split on the first blank line to separate headers from body.
    let mut header_block = raw;
    let mut body_block = "";
    if let Some(idx) = raw.find("\r\n\r\n").or_else(|| raw.find("\n\n")) {
        header_block = &raw[..idx];
        let after = if raw[idx..].starts_with("\r\n\r\n") {
            &raw[idx + 4..]
        } else {
            &raw[idx + 2..]
        };
        body_block = after;
    }

    let mut lines = header_block.lines();
    let request_line = lines.next()?.trim();
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    // The third token is the protocol (HTTP/1.1) — we don't need it.

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(idx) = line.find(':') {
            let name = line[..idx].trim().to_string();
            let value = line[idx + 1..].trim().to_string();
            if !name.is_empty() {
                headers.push((name, value));
            }
        }
    }

    Some(RawHttp {
        method,
        path,
        headers,
        body: body_block.to_string(),
    })
}

fn walkdir(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut results = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                results.extend(walkdir(&path));
            } else {
                results.push(path);
            }
        }
    }
    results
}

#[cfg(test)]
mod raw_http_tests {
    use super::*;

    #[test]
    fn simple_get() {
        let raw = "GET /admin HTTP/1.1\r\nHost: {{Hostname}}\r\nUser-Agent: cyweb\r\n\r\n";
        let r = parse_raw_http(raw).expect("parses");
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/admin");
        assert_eq!(r.headers.len(), 2);
        assert_eq!(r.headers[0], ("Host".into(), "{{Hostname}}".into()));
        assert_eq!(r.headers[1], ("User-Agent".into(), "cyweb".into()));
        assert!(r.body.is_empty());
    }

    #[test]
    fn post_with_body() {
        let raw = "POST /api/login HTTP/1.1\nHost: {{Hostname}}\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin&password=admin";
        let r = parse_raw_http(raw).expect("parses");
        assert_eq!(r.method, "POST");
        assert_eq!(r.path, "/api/login");
        assert_eq!(r.body, "username=admin&password=admin");
        assert_eq!(r.headers.len(), 2);
    }

    #[test]
    fn lf_only_separator() {
        // some templates use \n\n, not \r\n\r\n
        let raw = "GET /x HTTP/1.1\nHost: x\n\nbody";
        let r = parse_raw_http(raw).expect("parses");
        assert_eq!(r.method, "GET");
        assert_eq!(r.body, "body");
    }

    #[test]
    fn malformed_returns_none() {
        assert!(parse_raw_http("").is_none());
        assert!(parse_raw_http("not-a-request-line").is_none());
    }

    #[test]
    fn variable_placeholders_preserved() {
        let raw = "POST {{BaseURL}}/login HTTP/1.1\nHost: {{Hostname}}\n\n{{username}}={{password}}";
        let r = parse_raw_http(raw).expect("parses");
        assert_eq!(r.path, "{{BaseURL}}/login");
        assert_eq!(r.headers[0], ("Host".into(), "{{Hostname}}".into()));
        assert_eq!(r.body, "{{username}}={{password}}");
    }
}
