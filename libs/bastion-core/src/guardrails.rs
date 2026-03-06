/*
 * Bastion - Generic Security Engine
 * Copyright (C) 2026 motivationstudio,LLC
 */

use crate::text_guard::{Guard, ValidationResult};

pub fn validate_input(input: &str) -> ValidationResult {
    Guard::new().analyze(input)
}

pub fn validate_input_with_max_len(input: &str, max_len: usize) -> ValidationResult {
    Guard::new().max_len(max_len).analyze(input)
}
