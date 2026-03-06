/*
 * Bastion - Generic Security Engine
 * Copyright (C) 2026 motivationstudio,LLC
 */

use anyhow::Result;
use colored::*;
use std::fs;

const RECOMMENDED_PACKAGES: &[(&str, &str)] = &[
    ("defusedxml", "XML processing security (XXE mitigation)"),
    ("bandit", "Static analysis for security vulnerabilities"),
    ("pip-audit", "Dependency vulnerability checking"),
];

pub fn check_secure_requirements(requirements_path: &str) -> Result<()> {
    println!(
        "\n{}",
        "[+] Checking recommended security packages...".yellow()
    );

    let content = fs::read_to_string(requirements_path)?;
    let content_lower = content.to_lowercase();

    let mut missing_count = 0;

    for (package, description) in RECOMMENDED_PACKAGES {
        if content_lower.contains(&package.to_lowercase()) {
            println!("  {} {} is present", "✓".green().bold(), package);
        } else {
            println!(
                "  {} {} is missing — {}",
                "✗".red().bold(),
                package,
                description
            );
            missing_count += 1;
        }
    }

    if missing_count > 0 {
        println!(
            "\n  {} Run '{}' to generate recommended requirements.",
            "TIP:".cyan().bold(),
            "bastion init python".bold()
        );
    } else {
        println!(
            "  {}",
            "All recommended security packages are present!".green()
        );
    }

    Ok(())
}
