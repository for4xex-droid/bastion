/*
 * Bastion - Generic Security Engine
 * Copyright (C) 2026 motivationstudio,LLC
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 */

//! # Bastion Core - Security Protection Library
//!
//! A high-performance, industrial-grade security engine providing:
//! - `Jail` (fs_guard): File isolation and TOCTOU prevention.
//! - `Shield` (net_guard): SSRF and DNS Rebinding protection.
//! - `Guard` (text_guard): Prompt injection and DoS analyzer.

pub mod common;
pub mod guardrails;
pub mod python_check;

#[cfg(feature = "fs")]
pub mod fs_guard;

#[cfg(feature = "net")]
pub mod net_guard;

#[cfg(feature = "text")]
pub mod text_guard;

/// Initialize all security features with default policies.
pub fn initialize() {
    // Future integration point for global security policies
    tracing::info!("Bastion Core initialized.");
}
