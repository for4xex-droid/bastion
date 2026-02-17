# 🏰 Bastion Security Toolkit

[日本語](#jp) | [English](#en)

<a name="jp"></a>
## 🇯🇵 日本語

**"Vibe Coding を加速させる、産業グレードの安全装置。"**

Bastion は、直感と勢いで開発する「バイブコーディング（Vibe Coding）」スタイルの開発者が、安全性を犠牲にすることなく爆速で開発を続けるための Rust 製セキュリティツールキットです。

### 🚀 Concept: Vibe Coding × Rust Stability

バイブコーディングは楽しい。しかし、スピードを優先するあまり、パス・トラバーサル、SSRF、シークレットのハードコードといった致命的な脆弱性が紛れ込むリスクがあります。

Bastion は、開発者の「勢い（Vibe）」を妨げることなく、背後で物理的なガードレールを構築します。
**事実、Bastion 自体も 100% バイブコーディングによって開発されています。**

- **Rust による超拘束・高信頼**: 産業グレードのセキュリティロジックを 1 コマンドで導入。
- **思考の速度でスキャン**: プロジェクトの脆弱性や漏洩したシークレットを瞬時に検出。
- **物理 Jail による防御**: ファイルやネットワークへのアクセスを物理的に制限し、バグが悪用されるのを防ぎます。

> [!TIP]
> **なぜ Rust なのか？** [Bastion の思想的背景 (PHILOSOPHY.md)](PHILOSOPHY.md) を読む。

### ✨ 主な機能

- **🏰 File Jail (`fs_guard`)**: 指定ディレクトリ外へのアクセスを物理的に遮断。
- **🌐 Net Shield (`net_guard`)**: DNS Rebinding 対策を施した安全な HTTP クライアント。SSRF を物理的に防止。
- **🛡️ Analyzer & Sanitizer (`text_guard`)**: インジェクション攻撃や特殊文字を検知・無害化。
- **🔍 Security Scanner**: 脆弱性やハードコードされたシークレットを自動検出。
- **⚡ Quick Start**: `bastion init` で即座にガードレールを展開。

---

<a name="en"></a>
## 🇺🇸 English

**"Industrial-grade guardrails for Vibe Coders."**

Bastion is a Rust-based security toolkit designed for "Vibe Coding" — allowing developers to build at the speed of thought without compromising on security.

### 🚀 Concept: Vibe Coding × Rust Stability

Vibe coding is about flow. But in the rush of creation, it's easy to overlook critical vulnerabilities like path traversal, SSRF, or hardcoded secrets.

Bastion builds physical guardrails behind the scenes, ensuring your "Vibe" stays safe without slowing you down.
**In fact, Bastion itself is developed 100% using Vibe Coding.**

- **Rust-Powered Reliability**: Deploy industrial-grade security logic with a single command.
- **Scan at the Speed of Thought**: Instantly detect vulnerabilities and leaked secrets.
- **Physical Jail Defense**: Physically restrict file and network access to prevent exploits.

> [!TIP]
> **Why Rust?** Read our [Philosophy (PHILOSOPHY.md)](PHILOSOPHY.md) on Vibe Coding.

### ✨ Key Features

- **🏰 File Jail (`fs_guard`)**: Physically blocks access outside designated directories.
- **🌐 Net Shield (`net_guard`)**: Secure HTTP client with DNS Rebinding protection. Physically prevents SSRF.
- **🛡️ Analyzer & Sanitizer (`text_guard`)**: Detects and sanitizes injection attacks and malicious characters.
- **🔍 Security Scanner**: Automatically finds vulnerabilities and hardcoded secrets.
- **⚡ Quick Start**: Deploy guardrails instantly with `bastion init`.

---

## 🛠️ Quick Start

```bash
# Initialize security for your project
bastion init

# Run security scan
bastion scan
```

## 📜 License

MIT License - See [LICENSE](LICENSE) for details.

---

**🏰 Bastion - Build fast, stay safe.**
