# Contributing to Bastion

Thank you for your interest in making Bastion more secure! As an industrial-grade security engine, we have high standards for code quality and reliability.

## How to Contribute

1. **Fork the repository** and create your branch from `main`.
2. **Implement your changes**.
    - If adding a new guard, ensure it follows the `Trait` patterns used in `bastion-core`.
    - Performance is critical; avoid heavy allocations in the hot path.
3. **Add Tests**. 
    - Security logic must have 100% test coverage.
    - Include "Negative Tests" (trying to bypass your own guard).
4. **Run Audit**.
    ```bash
    cargo audit
    cargo clippy -- -D warnings
    cargo test
    ```
5. **Submit a Pull Request**.

## Coding Standards
- **Zero Panic**: Library code should never `panic!`. Always return `Result`.
- **Minimal Dependencies**: We aim to keep the dependency tree small to reduce the attack surface (Supply Chain Security).
- **Documentation**: All public APIs must be documented with examples.

## License
By contributing to Bastion, you agree that your contributions will be licensed under its AGPL-3.0 License.

---
Stay secure! 🏰
