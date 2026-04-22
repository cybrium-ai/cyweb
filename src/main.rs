//! cyweb — Fast web vulnerability scanner by Cybrium AI.
//!
//! Usage:
//!   cyweb scan <url> [--output json|sarif] [--threads N] [--timeout S]
//!   cyweb version

mod scanner;
mod signatures;
mod report;
mod crawler;

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
    },
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
        } => {
            print_banner();

            let config = scanner::ScanConfig {
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
            };

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
        Commands::Version => {
            println!(
                "cyweb {} — Cybrium AI Web Scanner\nhttps://github.com/cybrium-ai/cyweb",
                env!("CARGO_PKG_VERSION")
            );
        }
    }
}

fn print_banner() {
    eprintln!(
        "{}",
        r#"
   ___  _   _ __      __ ___  ___
  / __|| | | |\ \    / /| __|/ _ \
 | (__ | |_| | \ \/\/ / | _|| (_) |
  \___| \__, |  \_/\_/  |___|\___/
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
