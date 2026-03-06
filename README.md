# 🏰 Bastion 1.0

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Rust](https://img.shields.io/badge/language-Rust-orange.svg)](https://www.rust-lang.org/)

**Bastion** is an industrial-grade security engine designed to provide high-performance, programmable protection for AI agents and general applications. It moves beyond passive scanning to active, runtime defense-in-depth.

## 🚀 Key Features

Bastion 1.0 provides three core defensive layers ("The Three Guards"):

### 1. 🛡️ Jail (fs_guard)
A robust file system isolation layer.
- **Path Traversal Prevention**: Strict canonicalization and root enforcement.
- **TOCTOU Protection**: Atomic checks to prevent time-of-check to time-of-use attacks.
- **Symlink Protection**: Physical blocking of malicious symbolic links.

### 2. 📡 Shield (net_guard)
Advanced network access control.
- **SSRF Prevention**: Real-time DNS resolution checking against private/internal IP ranges.
- **DNS Rebinding Protection**: Validation of every outgoing request.
- **Strict Allowlisting**: Dynamic, endpoint-based communication policies.

### 3. 🧠 Guard (text_guard)
A specialized analyzer for AI inputs and outputs.
- **Prompt Injection Detection**: Heuristics to catch instruction override attempts.
- **DoS / Buffer Overflow Mitigation**: Intelligent length and complexity limits.
- **Safe Sanitization**: Unicode normalization (NFC) and bi-directional (Bidi) character removal.

## 🛠️ Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
bastion-core = { git = "https://github.com/for4xex-droid/bastion.git" }
```

## 💻 Usage

### Initializing a File Jail

```rust
use bastion_core::fs_guard::Jail;

let jail = Jail::init("./sandbox").unwrap();
// Only files within ./sandbox can be accessed
let mut file = jail.create_file("safe.txt").unwrap();
```

### Implementing Network Shield

```rust
use bastion_core::net_guard::ShieldClient;

let shield = ShieldClient::builder()
    .allow_endpoint("api.openai.com")
    .build()
    .unwrap();

// This will succeed
shield.get("https://api.openai.com/v1/models").await?;

// This will be blocked (Private IP / Not in allowlist)
shield.get("http://192.168.1.1/admin").await?;
```

## 🏗️ Project Structure

- `libs/bastion-core`: The core defensive library.
- `apps/bastion-cli`: CLI tool for security auditing and project initialization.

## 📜 License

Bastion is licensed under the **GNU Affero General Public License v3 (AGPL-3.0)**. For commercial licensing or proprietary integrations, please contact motivationstudio,LLC.

---
© 2026 motivationstudio,LLC. Part of the Aiome Ecosystem.
