/*
 * Bastion - Generic Security Engine
 * Copyright (C) 2026 motivationstudio,LLC
 */

use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use colored::*;
use regex::Regex;
use std::fs;
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;

use bastion_core::common::{self, ProjectType};
use bastion_core::python_check;

#[derive(Parser)]
#[command(name = "bastion")]
#[command(about = "Industrial-grade security toolkit", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// scan current directory for vulnerabilities and secrets
    Scan,
    /// Initialize security templates for the project
    Init {
        /// Language (rust, python, auto)
        #[arg(default_value = "auto")]
        language: String,
    },
}

const GUARDRAILS_TEMPLATE: &str = include_str!("../templates/guardrails_template.rs");
const SECURE_REQUIREMENTS_TEMPLATE: &str = include_str!("../templates/secure_requirements.txt");

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Scan => run_scan(),
        Commands::Init { language } => run_init(language),
    }
}

fn run_scan() -> Result<()> {
    println!("{}", "=== BASTION SECURITY CHECK START ===".bold().cyan());

    let project_type = common::detect_project_type();
    
    match project_type {
        ProjectType::Rust => {
            println!("{}", "[+] Rust Project Detected".green());
            run_rust_checks()?;
        }
        ProjectType::Python => {
            println!("{}", "[+] Python Project Detected".green());
            run_python_checks()?;
            if Path::new("requirements.txt").exists() {
                python_check::check_secure_requirements("requirements.txt")?;
            }
        }
        ProjectType::Unknown => {
            println!("{}", "[!] Generic Project / Unknown Language".yellow());
        }
    }

    println!("\n{}", "[+] Starting Secret Scan...".yellow());
    scan_for_secrets(".")?;

    println!("\n{}", "=== CHECK FINISHED ===".bold().cyan());
    Ok(())
}

fn run_rust_checks() -> Result<()> {
    println!("Running cargo audit...");
    if Command::new("cargo").args(["audit"]).status().is_err() {
        println!("{}", "Warning: 'cargo-audit' not found. Skip.".red());
    }

    println!("Running cargo clippy...");
    Command::new("cargo").args(["clippy", "--", "-D", "warnings"]).status()?;
    Ok(())
}

fn run_python_checks() -> Result<()> {
    println!("Running pip-audit...");
    if Command::new("pip-audit").status().is_err() {
        println!("{}", "Warning: 'pip-audit' not found. Skip.".red());
    }

    println!("Running bandit...");
    if Command::new("bandit").args(["-r", "."]).status().is_err() {
        println!("{}", "Warning: 'bandit' not found. Skip.".red());
    }
    Ok(())
}

fn scan_for_secrets(dir: &str) -> Result<()> {
    let re = Regex::new(
        r#"(?i) (api_key|password|secret|token|private_key|access_key|auth_token) \s*[:=]\s*['"]([a-zA-Z0-9_\-]{12,})['"]"#,
    ).unwrap();

    let walker = WalkDir::new(dir).into_iter();

    for entry in walker.filter_entry(|e| !common::is_ignored_path(e.path())) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();
            if is_scannable_file(path) {
                check_file_content(path, &re)?;
            }
        }
    }
    Ok(())
}

fn is_scannable_file(path: &Path) -> bool {
    path.extension()
        .and_then(|s| s.to_str())
        .map(|ext| matches!(ext, "rs" | "py" | "js" | "ts" | "env" | "json" | "toml" | "yaml" | "yml" | "md"))
        .unwrap_or(false)
}

fn check_file_content(path: &Path, re: &Regex) -> Result<()> {
    if let Ok(content) = fs::read_to_string(path) {
        for (i, line) in content.lines().enumerate() {
            if re.is_match(line) {
                println!(
                    "{} Found potential secret in {:?}:{} -> {}",
                    "[ALERT]".red().bold(),
                    path,
                    i + 1,
                    line.trim()
                );
            }
        }
    }
    Ok(())
}

pub fn run_init(language: &str) -> Result<()> {
    match language {
        "rust" => init_rust(),
        "python" => init_python(),
        "auto" => {
            println!("{}", "Detecting project type...".cyan());
            match common::detect_project_type() {
                ProjectType::Rust => init_rust(),
                ProjectType::Python => init_python(),
                ProjectType::Unknown => bail!("Could not auto-detect project type. Please specify 'rust' or 'python'."),
            }
        }
        _ => bail!(
            "Unknown language: '{}'. Supported: rust, python, auto",
            language
        ),
    }
}

fn init_rust() -> Result<()> {
    let target_path = "src/guardrails.rs";

    if Path::new(target_path).exists() {
        println!(
            "{} '{}' already exists. Skipping.",
            "Warning:".yellow().bold(),
            target_path
        );
        return Ok(());
    }

    if !Path::new("src").exists() {
        fs::create_dir_all("src")?;
    }

    fs::write(target_path, GUARDRAILS_TEMPLATE)?;
    println!("{} Generated '{}'", "✓".green().bold(), target_path);
    Ok(())
}

fn init_python() -> Result<()> {
    let target_path = "secure_requirements.txt";

    if Path::new(target_path).exists() {
        println!(
            "{} '{}' already exists. Skipping.",
            "Warning:".yellow().bold(),
            target_path
        );
        return Ok(());
    }

    fs::write(target_path, SECURE_REQUIREMENTS_TEMPLATE)?;
    println!("{} Generated '{}'", "✓".green().bold(), target_path);
    Ok(())
}
