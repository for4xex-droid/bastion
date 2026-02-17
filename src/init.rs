//! # Init - テンプレート生成モジュール
//!
//! `bastion init rust` / `bastion init python` で、
//! セキュリティ関連のテンプレートファイルをプロジェクトに展開する。

use anyhow::{bail, Result};
use colored::*;
use std::fs;
use std::path::Path;

/// guardrails テンプレート（バイナリに埋め込み）
const GUARDRAILS_TEMPLATE: &str = include_str!("../templates/guardrails_template.rs");

/// secure_requirements テンプレート（バイナリに埋め込み）
const SECURE_REQUIREMENTS_TEMPLATE: &str = include_str!("../templates/secure_requirements.txt");

/// 指定された言語のテンプレートを生成する
pub fn run_init(language: &str) -> Result<()> {
    match language {
        "rust" => init_rust(),
        "python" => init_python(),
        _ => bail!(
            "Unknown language: '{}'. Supported: rust, python",
            language
        ),
    }
}

fn init_rust() -> Result<()> {
    let target_path = "src/guardrails.rs";

    if Path::new(target_path).exists() {
        println!(
            "{} '{}' already exists. Skipping to avoid overwriting.",
            "Warning:".yellow().bold(),
            target_path
        );
        return Ok(());
    }

    // src/ ディレクトリが存在しない場合は作成
    if !Path::new("src").exists() {
        fs::create_dir_all("src")?;
    }

    fs::write(target_path, GUARDRAILS_TEMPLATE)?;

    println!(
        "{} Generated '{}'",
        "✓".green().bold(),
        target_path
    );
    println!();
    println!("  {} Add to your Cargo.toml:", "Next steps:".cyan().bold());
    println!("    regex = \"1.10\"");
    println!();
    println!("  Add to your main.rs:");
    println!("    mod guardrails;");
    println!("    use guardrails::validate_input;");

    Ok(())
}

fn init_python() -> Result<()> {
    let target_path = "secure_requirements.txt";

    if Path::new(target_path).exists() {
        println!(
            "{} '{}' already exists. Skipping to avoid overwriting.",
            "Warning:".yellow().bold(),
            target_path
        );
        return Ok(());
    }

    fs::write(target_path, SECURE_REQUIREMENTS_TEMPLATE)?;

    println!(
        "{} Generated '{}'",
        "✓".green().bold(),
        target_path
    );
    println!();
    println!(
        "  {} Append contents to your requirements.txt:",
        "Next steps:".cyan().bold()
    );
    println!("    cat secure_requirements.txt >> requirements.txt");
    println!("    pip install -r requirements.txt");

    Ok(())
}
