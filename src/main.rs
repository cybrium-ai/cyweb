//! cyweb — Fast web vulnerability scanner by Cybrium AI.
//!
//! Usage:
//!   cyweb scan <url> [--output json|sarif] [--threads N] [--timeout S]
//!   cyweb version

mod scanner;
mod signatures;
mod report;
mod crawler;
mod openapi;
mod checkpoint;
mod form_login;
mod evasion;
mod mutate;
mod fuzz;

use clap::{Parser, Subcommand};
use colored::Colorize;
use std::process;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(name = "cyweb", version, about = "Fast web vulnerability scanner by Cybrium AI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a target URL for vulnerabilities
    Scan {
        /// Target URL to scan (e.g., https://example.com)
        url: String,

        /// Output format: text, json, sarif
        #[arg(short, long, default_value = "text")]
        output: String,

        /// Number of concurrent threads
        #[arg(short, long, default_value = "10")]
        threads: usize,

        /// Request timeout in seconds
        #[arg(long, default_value = "10")]
        timeout: u64,

        /// Maximum path discovery depth
        #[arg(long, default_value = "200")]
        max_paths: usize,

        /// Follow redirects
        #[arg(long, default_value = "true")]
        follow_redirects: bool,

        /// Custom User-Agent string
        #[arg(long)]
        user_agent: Option<String>,

        /// Output file path (stdout if not specified)
        #[arg(short = 'f', long)]
        file: Option<String>,

        /// Enable spider/crawler to discover links
        #[arg(long)]
        spider: bool,

        /// Spider max depth
        #[arg(long, default_value = "3")]
        spider_depth: usize,

        /// Bearer token for authenticated scanning
        #[arg(long)]
        auth_bearer: Option<String>,

        /// Cookie header value (e.g., "session=abc123")
        #[arg(long)]
        auth_cookie: Option<String>,

        /// Basic auth (user:password)
        #[arg(long)]
        auth_basic: Option<String>,

        /// Custom header (repeatable, format: "Name: Value")
        #[arg(long = "header", short = 'H')]
        headers: Vec<String>,

        /// HTTP/SOCKS5 proxy URL (e.g., socks5://127.0.0.1:1080)
        #[arg(long)]
        proxy: Option<String>,

        /// Max requests per second (0 = unlimited)
        #[arg(long, default_value = "0")]
        rate_limit: u32,

        /// Enable TLS certificate analysis
        #[arg(long)]
        tls_check: bool,

        /// Extra YAML rules file
        #[arg(long)]
        rules: Option<String>,

        /// OpenAPI/Swagger spec URL to scan
        #[arg(long)]
        openapi: Option<String>,

        /// Resume a previously interrupted scan
        #[arg(long)]
        resume: bool,

        /// Form login: username (auto-detects login page and fields)
        #[arg(long)]
        login_user: Option<String>,

        /// Form login: password
        #[arg(long)]
        login_pass: Option<String>,

        /// Form login: explicit login page URL (optional, auto-discovered if omitted)
        #[arg(long)]
        login_url: Option<String>,

        /// Full scan with all 4,500+ rules (slower, more thorough)
        #[arg(long)]
        full: bool,

        /// Virtual host — override the Host header (e.g., internal.target.com)
        #[arg(long)]
        vhost: Option<String>,

        /// Client TLS certificate file (PEM)
        #[arg(long)]
        client_cert: Option<String>,

        /// Client TLS certificate key file (PEM)
        #[arg(long)]
        client_key: Option<String>,

        /// Tuning: scan only these categories (comma-separated)
        /// Categories: headers,paths,methods,server,rules,tls,cves,openapi,spider
        #[arg(long)]
        tuning: Option<String>,

        /// Save positive responses to this directory
        #[arg(long)]
        save: Option<String>,

        /// Disable DNS lookups (use IP directly)
        #[arg(long)]
        no_lookup: bool,

        /// Target platform filter: nix, win, all (filters path checks)
        #[arg(long, default_value = "all")]
        platform: String,

        /// Evasion technique (1-9): 1=URI encoding, 2=dir self-ref, 3=null byte,
        /// 4=random prepend, 5=fake param, 7=random case, 8=windows sep, 9=all
        #[arg(long, short = 'e')]
        evasion: Option<u8>,

        /// Mutate mode (1-6): 1=backup extensions, 2=password files,
        /// 3=Apache ~user, 4=cgiwrap, 5=common dirs, 6=all
        #[arg(long, short = 'm')]
        mutate: Option<u8>,

        /// Active fuzzing: inject SQLi, XSS, SSTI, CMDi, SSRF, path traversal
        /// payloads into discovered parameters and analyze responses
        #[arg(long)]
        fuzz: bool,

        /// Custom payloads directory for active fuzzing (YAML files)
        #[arg(long)]
        payloads: Option<String>,
    },
    /// Update signature rules from GitHub
    UpdateRules,
    /// Check for updates and self-update the binary
    Update,
    /// Show version info
    Version,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("cyweb=info".parse().unwrap()))
        .without_time()
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Scan {
            url,
            output,
            threads,
            timeout,
            max_paths,
            follow_redirects,
            user_agent,
            file,
            spider,
            spider_depth,
            auth_bearer,
            auth_cookie,
            auth_basic,
            headers,
            proxy,
            rate_limit,
            tls_check,
            rules,
            openapi,
            resume,
            full,
            login_user,
            login_pass,
            login_url,
            vhost,
            client_cert,
            client_key,
            tuning,
            save,
            no_lookup,
            platform,
            evasion,
            mutate,
            fuzz,
            payloads,
        } => {
            print_banner();

            let mut config = scanner::ScanConfig {
                target: url.clone(),
                threads,
                timeout_secs: timeout,
                max_paths,
                follow_redirects,
                user_agent: user_agent.unwrap_or_else(|| {
                    format!("cyweb/{} (https://cybrium.ai)", env!("CARGO_PKG_VERSION"))
                }),
                spider_enabled: spider,
                spider_depth,
                auth_bearer,
                auth_cookie,
                auth_basic,
                custom_headers: headers,
                proxy,
                rate_limit,
                tls_check,
                rules_file: rules,
                openapi_url: openapi,
                resume,
                full_scan: full,
                vhost: vhost.clone(),
                client_cert,
                client_key,
                tuning: tuning.clone(),
                save_dir: save,
                no_lookup,
                platform,
                evasion_mode: evasion.unwrap_or(0),
                mutate_mode: mutate.unwrap_or(0),
                fuzz_enabled: fuzz,
                payloads_dir: payloads,
            };

            // Form-based login: auto-detect login page, submit creds, inject cookies
            if let (Some(ref user), Some(ref pass)) = (&login_user, &login_pass) {
                eprintln!("{}", "Form login: authenticating...".cyan());
                let login_client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(config.timeout_secs))
                    .user_agent(&config.user_agent)
                    .cookie_store(true)
                    .danger_accept_invalid_certs(true)
                    .build()
                    .unwrap();
                let result = form_login::form_login(
                    &login_client,
                    &config.target,
                    user,
                    pass,
                    login_url.as_deref(),
                ).await;
                if result.success {
                    eprintln!("  {} Logged in (cookies: {})", "OK".green().bold(), &result.cookies[..result.cookies.len().min(50)]);
                    // Inject session cookies into the scan config
                    config.auth_cookie = Some(match config.auth_cookie {
                        Some(existing) => format!("{existing}; {}", result.cookies),
                        None => result.cookies,
                    });
                } else {
                    eprintln!("  {} {}", "FAILED".red().bold(), result.error.unwrap_or_default());
                    eprintln!("  Continuing scan without authentication");
                }
            }

            eprintln!(
                "{} {} (threads={}, timeout={}s)",
                "TARGET".cyan().bold(),
                url.white().bold(),
                threads,
                timeout
            );
            eprintln!();

            let result = scanner::run_scan(config).await;

            match output.as_str() {
                "json" => {
                    let json = report::to_json(&result);
                    if let Some(path) = &file {
                        std::fs::write(path, &json).expect("Failed to write output file");
                        eprintln!("\n{} {}", "Report written to".green(), path);
                    } else {
                        println!("{json}");
                    }
                }
                "sarif" => {
                    let sarif = report::to_sarif(&result);
                    if let Some(path) = &file {
                        std::fs::write(path, &sarif).expect("Failed to write output file");
                        eprintln!("\n{} {}", "SARIF report written to".green(), path);
                    } else {
                        println!("{sarif}");
                    }
                }
                "csv" => {
                    let csv = report::to_csv(&result);
                    if let Some(path) = &file {
                        std::fs::write(path, &csv).expect("Failed to write output file");
                        eprintln!("\n{} {}", "CSV report written to".green(), path);
                    } else {
                        println!("{csv}");
                    }
                }
                "xml" => {
                    let xml = report::to_xml(&result);
                    if let Some(path) = &file {
                        std::fs::write(path, &xml).expect("Failed to write output file");
                        eprintln!("\n{} {}", "XML report written to".green(), path);
                    } else {
                        println!("{xml}");
                    }
                }
                "html" | "htm" => {
                    let html = report::to_html(&result);
                    if let Some(path) = &file {
                        std::fs::write(path, &html).expect("Failed to write output file");
                        eprintln!("\n{} {}", "HTML report written to".green(), path);
                    } else {
                        println!("{html}");
                    }
                }
                _ => {
                    report::print_text(&result);
                    if let Some(path) = &file {
                        let json = report::to_json(&result);
                        std::fs::write(path, &json).expect("Failed to write output file");
                        eprintln!("\n{} {}", "Report written to".green(), path);
                    }
                }
            }

            let exit_code = if result.findings.is_empty() { 0 } else { 1 };
            process::exit(exit_code);
        }
        Commands::UpdateRules => {
            eprintln!("Fetching latest rules from GitHub...");
            let url = "https://raw.githubusercontent.com/cybrium-ai/cyweb/main/rules/default.yaml";
            match reqwest::get(url).await {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let body = resp.text().await.unwrap_or_default();
                        let rules_dir = dirs::home_dir()
                            .map(|h| h.join(".cyweb"))
                            .unwrap_or_else(|| std::path::PathBuf::from(".cyweb"));
                        std::fs::create_dir_all(&rules_dir).ok();
                        let path = rules_dir.join("default.yaml");
                        std::fs::write(&path, &body).expect("Failed to write rules file");
                        // Count rules
                        let count = body.matches("- id:").count();
                        eprintln!(
                            "{} {} rules saved to {}",
                            "Updated!".green().bold(),
                            count,
                            path.display()
                        );
                    } else {
                        eprintln!("{} HTTP {}", "Failed:".red(), resp.status());
                        process::exit(2);
                    }
                }
                Err(e) => {
                    eprintln!("{} {}", "Failed:".red(), e);
                    process::exit(2);
                }
            }
        }
        Commands::Update => {
            let current = env!("CARGO_PKG_VERSION");
            eprintln!("Current version: {}", current.yellow());
            eprintln!("Checking for updates...");

            // Fetch latest release from GitHub API
            let client = reqwest::Client::builder()
                .user_agent(format!("cyweb/{current}"))
                .build()
                .unwrap();

            match client.get("https://api.github.com/repos/cybrium-ai/cyweb/releases/latest")
                .header("Accept", "application/vnd.github+json")
                .send().await
            {
                Ok(resp) if resp.status().is_success() => {
                    let data: serde_json::Value = resp.json().await.unwrap_or_default();
                    let latest = data["tag_name"].as_str().unwrap_or("unknown").trim_start_matches('v');

                    if latest == current {
                        eprintln!("{}", "Already up to date!".green().bold());
                        return;
                    }

                    eprintln!("New version available: {} -> {}", current.dimmed(), latest.green().bold());

                    // Determine platform binary name
                    let binary_name = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
                        "cyweb-darwin-arm64"
                    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
                        "cyweb-darwin-amd64"
                    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
                        "cyweb-linux-arm64"
                    } else {
                        "cyweb-linux-amd64"
                    };

                    // Find download URL
                    let assets = data["assets"].as_array();
                    let download_url = assets.and_then(|a| {
                        a.iter().find(|asset| {
                            asset["name"].as_str().map_or(false, |n| n == binary_name)
                        }).and_then(|asset| asset["browser_download_url"].as_str())
                    });

                    let url = match download_url {
                        Some(u) => u,
                        None => {
                            eprintln!("{} No binary found for your platform ({})", "Error:".red(), binary_name);
                            process::exit(2);
                        }
                    };

                    eprintln!("Downloading {}...", binary_name);
                    match client.get(url).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let bytes = resp.bytes().await.unwrap_or_default();
                            if bytes.is_empty() {
                                eprintln!("{} Download returned empty", "Error:".red());
                                process::exit(2);
                            }

                            // Get current executable path
                            let exe_path = std::env::current_exe().expect("Cannot determine executable path");
                            let backup = exe_path.with_extension("old");

                            // Backup current → replace → make executable
                            if let Err(e) = std::fs::rename(&exe_path, &backup) {
                                eprintln!("{} Cannot backup current binary: {}", "Error:".red(), e);
                                eprintln!("Try: sudo cyweb update");
                                process::exit(2);
                            }

                            if let Err(e) = std::fs::write(&exe_path, &bytes) {
                                // Restore backup
                                std::fs::rename(&backup, &exe_path).ok();
                                eprintln!("{} Cannot write new binary: {}", "Error:".red(), e);
                                process::exit(2);
                            }

                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                std::fs::set_permissions(&exe_path, std::fs::Permissions::from_mode(0o755)).ok();
                            }

                            // Remove backup
                            std::fs::remove_file(&backup).ok();

                            eprintln!("{} Updated to v{}", "Success!".green().bold(), latest);

                            // Also update rules
                            eprintln!("Updating rules...");
                            if let Ok(r) = client.get("https://raw.githubusercontent.com/cybrium-ai/cyweb/main/rules/default.yaml").send().await {
                                if r.status().is_success() {
                                    let body = r.text().await.unwrap_or_default();
                                    let rules_dir = dirs::home_dir()
                                        .map(|h| h.join(".cyweb"))
                                        .unwrap_or_else(|| std::path::PathBuf::from(".cyweb"));
                                    std::fs::create_dir_all(&rules_dir).ok();
                                    std::fs::write(rules_dir.join("default.yaml"), &body).ok();
                                    let count = body.matches("- id:").count();
                                    eprintln!("  {} rules updated", count);
                                }
                            }
                        }
                        _ => {
                            eprintln!("{} Download failed", "Error:".red());
                            process::exit(2);
                        }
                    }
                }
                _ => {
                    eprintln!("{} Cannot reach GitHub API", "Error:".red());
                    process::exit(2);
                }
            }
        }
        Commands::Version => {
            let current = env!("CARGO_PKG_VERSION");
            println!("cyweb {} — Cybrium AI Web Scanner", current);
            println!("https://github.com/cybrium-ai/cyweb");

            // Check for updates in background
            let client = reqwest::Client::builder()
                .user_agent(format!("cyweb/{current}"))
                .timeout(std::time::Duration::from_secs(3))
                .build()
                .unwrap();
            if let Ok(resp) = client.get("https://api.github.com/repos/cybrium-ai/cyweb/releases/latest")
                .header("Accept", "application/vnd.github+json")
                .send().await
            {
                if let Ok(data) = resp.json::<serde_json::Value>().await {
                    let latest = data["tag_name"].as_str().unwrap_or("").trim_start_matches('v');
                    if !latest.is_empty() && latest != current {
                        println!(
                            "\n{} v{} available (run: {})",
                            "Update:".yellow().bold(),
                            latest.green(),
                            "cyweb update".cyan()
                        );
                    }
                }
            }
        }
    }
}

fn print_banner() {
    eprintln!(
        "{}",
        r#"
   ___  _   _ __      __ ___  ___
  / __|| | | |\ \    / /| __|| _ \
 | (__ | |_| | \ \/\/ / | _| | _ \
  \___| \__, |  \_/\_/  |___||___/
        |___/
"#
        .purple()
    );
    eprintln!(
        "  {} v{} — {}",
        "cyweb".purple().bold(),
        env!("CARGO_PKG_VERSION"),
        "Cybrium AI Web Scanner".dimmed()
    );
    eprintln!();
}
