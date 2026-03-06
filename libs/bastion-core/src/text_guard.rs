/*
 * Bastion - Generic Security Engine
 * Copyright (C) 2026 motivationstudio,LLC
 */

use regex::Regex;
use std::sync::OnceLock;

#[cfg(feature = "text")]
use unicode_normalization::UnicodeNormalization;

#[derive(Debug, PartialEq, Eq)]
pub enum ValidationResult {
    Valid,
    Blocked(String),
}

pub struct Guard {
    max_len: usize,
}

impl Default for Guard {
    fn default() -> Self {
        Self { max_len: 4096 }
    }
}

static INJECTION_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();

fn get_patterns() -> &'static Vec<Regex> {
    INJECTION_PATTERNS.get_or_init(|| {
        vec![
            Regex::new(r"(?i)ignore previous instructions").unwrap(),
            Regex::new(r"(?i)ignore all instructions").unwrap(),
            Regex::new(r"(?i)disregard.*instructions").unwrap(),
            Regex::new(r"(?i)system prompt").unwrap(),
            Regex::new(r"(?i)you are an ai").unwrap(),
            Regex::new(r"(?i)new instructions:").unwrap(),
            Regex::new(r"(?i)override.*system").unwrap(),
            Regex::new(r"(?i)<script").unwrap(),
            Regex::new(r"(?i)javascript:").unwrap(),
            Regex::new(r"(?i)vbscript:").unwrap(),
            Regex::new(r"(?i)data:text/html").unwrap(),
            Regex::new(r#"(?i)alert\("#).unwrap(),
            Regex::new(r"(?i);\s*rm\s+-").unwrap(),
            Regex::new(r"(?i)\|\|\s*curl").unwrap(),
            Regex::new(r"(?i)\|\|\s*wget").unwrap(),
        ]
    })
}

impl Guard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn max_len(mut self, len: usize) -> Self {
        self.max_len = len;
        self
    }

    pub fn analyze(&self, input: &str) -> ValidationResult {
        if input.len() > self.max_len {
            return ValidationResult::Blocked(format!(
                "Input too long (max {} bytes, got {})",
                self.max_len,
                input.len()
            ));
        }

        let patterns = get_patterns();
        for re in patterns {
            if re.is_match(input) {
                return ValidationResult::Blocked("Potential injection detected".to_string());
            }
        }

        ValidationResult::Valid
    }

    pub fn sanitize(&self, input: &str) -> String {
        let mut text = if input.len() > self.max_len {
            input[..self.max_len].to_string()
        } else {
            input.to_string()
        };

        #[cfg(feature = "text")]
        {
            text = text.nfc().collect::<String>();
        }

        text = text.chars().filter(|&c| !self.is_forbidden_char(c)).collect();
        text = self.mask_windows_reserved(&text);
        text
    }

    fn is_forbidden_char(&self, c: char) -> bool {
        if c.is_control() {
            if c == '\n' || c == '\t' {
                return false;
            }
            return true;
        }
        match c {
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202A}' | '\u{202B}'..='\u{202B}' | 
            '\u{202C}'..='\u{202C}' | '\u{202D}'..='\u{202D}' | '\u{202E}'..='\u{202E}' |
            '\u{2066}'..='\u{2069}' => return true,
            _ => {}
        }
        matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    }

    fn mask_windows_reserved(&self, name: &str) -> String {
        let upper = name.to_uppercase();
        let reserved = [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];

        if reserved.contains(&upper.as_str()) {
            format!("_{}", name)
        } else {
            name.to_string()
        }
    }
}
