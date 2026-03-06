/*
 * Bastion - Generic Security Engine
 * Copyright (C) 2026 motivationstudio,LLC
 */

use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectType {
    Rust,
    Python,
    Unknown,
}

pub fn detect_project_type() -> ProjectType {
    if Path::new("Cargo.toml").exists() {
        return ProjectType::Rust;
    }
    if Path::new("requirements.txt").exists() || Path::new("pyproject.toml").exists() {
        return ProjectType::Python;
    }
    ProjectType::Unknown
}

pub fn is_ignored_path(path: &Path) -> bool {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    name.starts_with('.') || 
    matches!(name, "target" | "node_modules" | "venv" | ".venv" | "__pycache__" | "dist" | "build")
}
