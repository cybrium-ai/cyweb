//! Request evasion techniques — encode/transform URLs to bypass WAFs and filters.
//!
//! Mirrors Nikto's evasion modes 1-8 + A/B:
//!   1 — Random URI encoding (non-UTF8)
//!   2 — Directory self-reference (/./path)
//!   3 — Premature URL ending (%00)
//!   4 — Prepend long random string
//!   5 — Fake parameter
//!   6 — TAB as request spacer (via header trick)
//!   7 — Random case of the URL
//!   8 — Windows directory separator (\)
//!   9 — All of the above (combined)

use rand::Rng;

/// Apply evasion transforms to a URL path.
pub fn apply(path: &str, mode: u8) -> Vec<String> {
    match mode {
        1 => vec![random_uri_encode(path)],
        2 => vec![dir_self_reference(path)],
        3 => vec![premature_url_end(path)],
        4 => vec![prepend_random(path)],
        5 => vec![fake_parameter(path)],
        6 => vec![path.to_string()], // TAB spacer is a transport-level trick, path stays same
        7 => vec![random_case(path)],
        8 => vec![windows_separator(path)],
        9 => {
            // All techniques — return multiple variants
            vec![
                random_uri_encode(path),
                dir_self_reference(path),
                premature_url_end(path),
                prepend_random(path),
                fake_parameter(path),
                random_case(path),
                windows_separator(path),
            ]
        }
        _ => vec![path.to_string()],
    }
}

/// Mode 1: Randomly percent-encode some characters that don't need encoding.
fn random_uri_encode(path: &str) -> String {
    let mut rng = rand::thread_rng();
    path.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() && rng.gen_bool(0.3) {
                format!("%{:02X}", c as u8)
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Mode 2: Insert directory self-references /./ into the path.
fn dir_self_reference(path: &str) -> String {
    path.replace("/", "/./")
}

/// Mode 3: Append a null byte (URL-encoded) to attempt premature URL termination.
fn premature_url_end(path: &str) -> String {
    format!("{path}%00")
}

/// Mode 4: Prepend a long random directory that doesn't exist, then traverse back.
fn prepend_random(path: &str) -> String {
    let mut rng = rand::thread_rng();
    let random_dir: String = (0..12)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();
    format!("/{random_dir}/../..{path}")
}

/// Mode 5: Add a fake query parameter to bypass simple URL-based filters.
fn fake_parameter(path: &str) -> String {
    let mut rng = rand::thread_rng();
    let param: String = (0..6)
        .map(|_| rng.sample(rand::distributions::Alphanumeric) as char)
        .collect();
    if path.contains('?') {
        format!("{path}&{param}=1")
    } else {
        format!("{path}?{param}=1")
    }
}

/// Mode 7: Randomize the case of path characters.
fn random_case(path: &str) -> String {
    let mut rng = rand::thread_rng();
    path.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() && rng.gen_bool(0.5) {
                if c.is_uppercase() {
                    c.to_lowercase().next().unwrap_or(c)
                } else {
                    c.to_uppercase().next().unwrap_or(c)
                }
            } else {
                c
            }
        })
        .collect()
}

/// Mode 8: Replace forward slashes with backslashes (Windows IIS trick).
fn windows_separator(path: &str) -> String {
    path.replace("/", "\\")
}

/// Describe evasion modes for help text.
pub fn describe(mode: u8) -> &'static str {
    match mode {
        1 => "Random URI encoding",
        2 => "Directory self-reference (/./)",
        3 => "Premature URL ending (%00)",
        4 => "Prepend long random path + traverse back",
        5 => "Fake query parameter",
        6 => "TAB as request spacer",
        7 => "Random case URL",
        8 => "Windows directory separator (\\)",
        9 => "All techniques combined",
        _ => "None",
    }
}
