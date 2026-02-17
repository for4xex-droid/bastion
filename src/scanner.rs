//! # Scanner - 脆弱性スキャンモジュール
//!
//! Rust / Python プロジェクトの脆弱性スキャン・シークレット検出を行う。

use anyhow::Result;
use colored::*;
use regex::Regex;
use std::fs;
use std::path::Path;
use std::process::Command;
use walkdir::WalkDir;

use crate::python_check;

/// メインのスキャン処理を実行する
pub fn run_scan() -> Result<()> {
    println!("{}", "=== BASTION SECURITY CHECK START ===".bold().cyan());

    let current_dir = ".";

    // 1. プロジェクト種類の判定とツール実行
    if Path::new("Cargo.toml").exists() {
        println!("{}", "[+] Rust Project Detected".green());
        run_rust_checks()?;
    }

    if Path::new("requirements.txt").exists() || Path::new("pyproject.toml").exists() {
        println!("{}", "[+] Python Project Detected".green());
        run_python_checks()?;

        // 推奨ライブラリチェック
        if Path::new("requirements.txt").exists() {
            python_check::check_secure_requirements("requirements.txt")?;
        }
    }

    // 2. シークレットスキャン（全言語共通）
    println!("{}", "\n[+] Starting Secret Scan...".yellow());
    scan_for_secrets(current_dir)?;

    println!("{}", "\n=== CHECK FINISHED ===".bold().cyan());
    Ok(())
}

fn run_rust_checks() -> Result<()> {
    // cargo audit (脆弱性DBチェック)
    println!("Running cargo audit...");
    let status = Command::new("cargo").args(["audit"]).status();

    if status.is_err() {
        println!(
            "{}",
            "Warning: 'cargo-audit' not found. Install via 'cargo install cargo-audit'".red()
        );
    }

    // cargo clippy (Lintチェック)
    println!("Running cargo clippy...");
    Command::new("cargo")
        .args(["clippy", "--", "-D", "warnings"])
        .status()?;

    Ok(())
}

fn run_python_checks() -> Result<()> {
    // pip-audit
    println!("Running pip-audit...");
    let status = Command::new("pip-audit").status();
    if status.is_err() {
        println!(
            "{}",
            "Warning: 'pip-audit' not found. Install via 'pip install pip-audit'".red()
        );
    }

    // bandit
    println!("Running bandit...");
    let status = Command::new("bandit").args(["-r", "."]).status();
    if status.is_err() {
        println!(
            "{}",
            "Warning: 'bandit' not found. Install via 'pip install bandit'".red()
        );
    }

    Ok(())
}

fn scan_for_secrets(dir: &str) -> Result<()> {
    let re = Regex::new(
        r#"(?i)(api_key|password|secret|token|private_key).*=.*['""][a-zA-Z0-9]{8,}['""]"#,
    )
    .unwrap();

    let walker = WalkDir::new(dir).into_iter();

    for entry in walker.filter_entry(|e| !is_hidden(e)) {
        let entry = entry?;
        if entry.file_type().is_file() {
            let path = entry.path();

            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy();
                if matches!(
                    ext_str.as_ref(),
                    "rs" | "py" | "js" | "ts" | "env" | "json" | "toml" | "yaml" | "yml"
                ) {
                    check_file_content(path, &re)?;
                }
            }
        }
    }
    Ok(())
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

/// .git などの隠しファイルや target ディレクトリを除外
fn is_hidden(entry: &walkdir::DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| {
            s.starts_with('.')
                || s == "target"
                || s == "node_modules"
                || s == "venv"
                || s == ".venv"
        })
        .unwrap_or(false)
}
