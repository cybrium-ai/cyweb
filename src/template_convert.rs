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

    // v0.8.4 — Workflow templates have a top-level `workflows:` block
    // instead of `http:`/`requests:`. They reference other templates
    // by relative path and conditionally chain follow-up templates
    // when a parent matches. Convert these into a dedicated cyweb
    // template kind so the runtime can execute them in dependency
    // order.
    let workflows = tmpl.get("workflows");
    let http = tmpl.get("http").or_else(|| tmpl.get("requests"));
    // v0.8.5 — DNS / TCP / headless are now first-class template kinds
    // with runtime support in `protocol_runners`. The converter emits
    // them verbatim (matchers + extractors are the same shape) and the
    // runtime dispatches based on which block is present.
    let dns = tmpl.get("dns");
    let tcp = tmpl.get("tcp")
        .or_else(|| tmpl.get("network")); // upstream legacy alias
    let is_headless = tmpl.get("headless").is_some()
        || tmpl.get("info")
            .and_then(|i| i.get("tags"))
            .and_then(|t| t.as_str())
            .map(|s| s.split(',').any(|tag| tag.trim() == "headless"))
            .unwrap_or(false);

    if workflows.is_none() && http.is_none() && dns.is_none() && tcp.is_none() && !is_headless {
        return Err("Template has no executable block (http / requests / dns / tcp / workflows / headless)".into());
    }

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

    // v0.8.4 — workflow path. Emit a `workflows:` block with each
    // referenced template's path + matchers + nested subtemplates
    // preserved. cyweb's runtime reads this and executes the
    // referenced templates in order, chaining subtemplates when the
    // parent's matchers fire.
    if let Some(wf) = workflows {
        if let Some(wf_seq) = wf.as_sequence() {
            let converted: Vec<serde_yaml::Value> = wf_seq.iter()
                .map(convert_workflow_step)
                .collect();
            output.insert(
                serde_yaml::Value::String("workflows".into()),
                serde_yaml::Value::Sequence(converted),
            );
        }
        return serde_yaml::to_string(&serde_yaml::Value::Mapping(output))
            .map_err(|e| format!("Serialization error: {}", e));
    }

    // v0.8.5 — DNS path. Upstream DNS templates use:
    //   dns:
    //     - name: "{{FQDN}}"
    //       type: TXT
    //       matchers: [...]
    // We emit the same shape; cyweb's runtime resolves it via
    // hickory-resolver and runs matchers against the answer.
    if let Some(dns_block) = dns {
        if let Some(seq) = dns_block.as_sequence() {
            let converted: Vec<serde_yaml::Value> = seq.iter()
                .map(convert_dns_step)
                .collect();
            output.insert(
                serde_yaml::Value::String("dns".into()),
                serde_yaml::Value::Sequence(converted),
            );
        }
    }

    // v0.8.5 — TCP path. Upstream uses `network:` historically and
    // `tcp:` in newer templates; both map to cyweb's `tcp:` block.
    if let Some(tcp_block) = tcp {
        if let Some(seq) = tcp_block.as_sequence() {
            let converted: Vec<serde_yaml::Value> = seq.iter()
                .map(convert_tcp_step)
                .collect();
            output.insert(
                serde_yaml::Value::String("tcp".into()),
                serde_yaml::Value::Sequence(converted),
            );
        }
    }

    // If a template is DNS-only or TCP-only (no HTTP requests), emit
    // and return — there's nothing else to convert.
    if http.is_none() && (dns.is_some() || tcp.is_some()) {
        return serde_yaml::to_string(&serde_yaml::Value::Mapping(output))
            .map_err(|e| format!("Serialization error: {}", e));
    }

    // Headless-only path (templates tagged "headless" with no http
    // block). Tag is preserved in info_out above; runtime sees the
    // tag and dispatches through the chromiumoxide path. If the
    // template ALSO has http requests, those convert as normal and
    // the runtime's headless dispatch picks one path.
    if http.is_none() && is_headless {
        return serde_yaml::to_string(&serde_yaml::Value::Mapping(output))
            .map_err(|e| format!("Serialization error: {}", e));
    }

    // HTTP path — fall through with `http` (which we know is Some
    // here because the early-return guard above caught the
    // "neither workflows nor http" case).
    let http = http.ok_or("internal: http unset after guard")?;
    let requests_arr = http.as_sequence()
        .ok_or("http/requests is not a list")?;

    let mut steps = Vec::new();
    for req in requests_arr {
        let step = convert_request_step(req)?;
        steps.push(step);
    }
    output.insert(serde_yaml::Value::String("requests".into()), serde_yaml::Value::Sequence(steps));

    serde_yaml::to_string(&serde_yaml::Value::Mapping(output))
        .map_err(|e| format!("Serialization error: {}", e))
}

/// Convert a single workflow step entry. Each entry references a
/// template (by path or tag) and optionally includes match
/// conditions + nested subtemplates that fire only when the parent
/// matches. We preserve the structure verbatim — runtime handles
/// the chaining logic.
fn convert_workflow_step(step: &serde_yaml::Value) -> serde_yaml::Value {
    let mut out = serde_yaml::Mapping::new();

    // template path or tags reference
    if let Some(t) = step.get("template") {
        out.insert(serde_yaml::Value::String("template".into()), t.clone());
    }
    if let Some(t) = step.get("tags") {
        out.insert(serde_yaml::Value::String("tags".into()), t.clone());
    }

    // matchers — used to gate subtemplates
    if let Some(m) = step.get("matchers") {
        out.insert(serde_yaml::Value::String("matchers".into()), m.clone());
    }

    // subtemplates — recursively converted (nested workflow chains)
    if let Some(subs) = step.get("subtemplates") {
        if let Some(seq) = subs.as_sequence() {
            let nested: Vec<serde_yaml::Value> = seq.iter()
                .map(convert_workflow_step)
                .collect();
            out.insert(
                serde_yaml::Value::String("subtemplates".into()),
                serde_yaml::Value::Sequence(nested),
            );
        }
    }

    serde_yaml::Value::Mapping(out)
}

/// v0.8.5 — DNS step converter. Upstream schema:
///   - name: "{{FQDN}}"
///     type: TXT
///     matchers: [...]
fn convert_dns_step(step: &serde_yaml::Value) -> serde_yaml::Value {
    let mut out = serde_yaml::Mapping::new();
    if let Some(n) = step.get("name") {
        out.insert(serde_yaml::Value::String("name".into()), n.clone());
    } else {
        out.insert(serde_yaml::Value::String("name".into()), serde_yaml::Value::String("{{Hostname}}".into()));
    }
    let qtype = step.get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("A")
        .to_uppercase();
    out.insert(serde_yaml::Value::String("type".into()), serde_yaml::Value::String(qtype));
    if let Some(m) = step.get("matchers") {
        out.insert(serde_yaml::Value::String("matchers".into()), m.clone());
    }
    if let Some(e) = step.get("extractors") {
        out.insert(serde_yaml::Value::String("extractors".into()), e.clone());
    }
    serde_yaml::Value::Mapping(out)
}

/// v0.8.5 — TCP step converter. Upstream schema:
///   - host: ["{{Hostname}}:21"]
///     inputs: [{data: "..."}]
///     read-size: 4096
///     matchers: [...]
fn convert_tcp_step(step: &serde_yaml::Value) -> serde_yaml::Value {
    let mut out = serde_yaml::Mapping::new();
    // host can be string or sequence; we collapse to first element
    // (cyweb's runtime takes a single host:port string per step).
    let host = match step.get("host") {
        Some(serde_yaml::Value::Sequence(seq)) => seq.first().cloned()
            .unwrap_or(serde_yaml::Value::String("{{Hostname}}".into())),
        Some(v) => v.clone(),
        None => serde_yaml::Value::String("{{Hostname}}".into()),
    };
    out.insert(serde_yaml::Value::String("host".into()), host);
    // `inputs` is a list of {data: ...} maps in upstream; we take
    // the first input's data field as the payload to send.
    if let Some(inputs) = step.get("inputs") {
        if let Some(seq) = inputs.as_sequence() {
            if let Some(first) = seq.first() {
                if let Some(data) = first.get("data") {
                    out.insert(serde_yaml::Value::String("data".into()), data.clone());
                }
            }
        }
    } else if let Some(data) = step.get("data") {
        out.insert(serde_yaml::Value::String("data".into()), data.clone());
    }
    if let Some(m) = step.get("matchers") {
        out.insert(serde_yaml::Value::String("matchers".into()), m.clone());
    }
    if let Some(e) = step.get("extractors") {
        out.insert(serde_yaml::Value::String("extractors".into()), e.clone());
    }
    serde_yaml::Value::Mapping(out)
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

#[cfg(test)]
mod workflow_tests {
    use super::*;

    #[test]
    fn workflow_template_converts() {
        let yaml = r#"
id: test-workflow
info:
  name: Test workflow
  severity: high
workflows:
  - template: cves/2021/CVE-2021-12345.yaml
    matchers:
      - name: vulnerable
    subtemplates:
      - template: exploits/follow-up.yaml
"#;
        let result = convert_single(yaml).expect("workflow templates should convert");
        assert!(result.contains("workflows:"), "output should contain workflows block");
        assert!(result.contains("CVE-2021-12345.yaml"), "should preserve template path");
        assert!(result.contains("follow-up.yaml"), "should preserve subtemplate");
    }

    #[test]
    fn workflow_with_tags_selector() {
        let yaml = r#"
id: tag-workflow
info: { name: Tag workflow, severity: low }
workflows:
  - tags: [cve, rce]
"#;
        let result = convert_single(yaml).expect("tag-selector workflow converts");
        assert!(result.contains("tags:"));
    }

    #[test]
    fn empty_template_rejected() {
        // v0.8.5 — DNS/TCP/headless are now accepted; the rejection
        // path only fires when the template has NONE of the executable
        // blocks at all.
        let yaml = r#"
id: nothing
info: { name: nothing, severity: info }
"#;
        let err = convert_single(yaml).expect_err("template with no executable block is rejected");
        assert!(err.contains("no executable block"));
    }

    #[test]
    fn dns_only_template_converts() {
        let yaml = r#"
id: dns-only
info: { name: DNS only, severity: info }
dns:
  - name: "{{FQDN}}"
    type: TXT
    matchers:
      - type: word
        words: ["v=spf1"]
"#;
        let result = convert_single(yaml).expect("DNS-only converts in v0.8.5");
        assert!(result.contains("dns:"));
        assert!(result.contains("type: TXT"));
        assert!(result.contains("v=spf1"));
    }

    #[test]
    fn tcp_only_template_converts() {
        let yaml = r#"
id: tcp-banner
info: { name: TCP banner, severity: info }
tcp:
  - host: ["{{Hostname}}:21"]
    inputs:
      - data: ""
    matchers:
      - type: word
        words: ["220"]
"#;
        let result = convert_single(yaml).expect("TCP-only converts in v0.8.5");
        assert!(result.contains("tcp:"));
        assert!(result.contains("{{Hostname}}:21"));
    }

    #[test]
    fn network_alias_for_tcp_converts() {
        // upstream legacy used `network:` instead of `tcp:`
        let yaml = r#"
id: network-banner
info: { name: Network banner, severity: info }
network:
  - host: ["{{Hostname}}:1433"]
    inputs:
      - data: "x"
    matchers:
      - type: word
        words: ["MSSQL"]
"#;
        let result = convert_single(yaml).expect("network: alias accepted");
        assert!(result.contains("tcp:"));
    }

    #[test]
    fn headless_only_template_converts() {
        let yaml = r#"
id: headless-only
info:
  name: Headless template
  severity: info
  tags: cve,headless
"#;
        let result = convert_single(yaml).expect("headless-tagged template converts");
        assert!(result.contains("headless"));
    }
}
