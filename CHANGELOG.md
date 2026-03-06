# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3] - 2026-03-05

### Added
- **Adaptive Scanning Engine**: Implemented reconnaissance probes that skip hardened agents and aggressively exploit vulnerable ones, significantly improving scan speed.
- **Smart Heuristics Detection**: Pattern-based classification for Windows/Unix command outputs, paths, and credentials (replaces brittle keyword lists).
- **LLM-Enhanced Detection**: Added `--ai` flag to use LLMs (DeepSeek, Groq, etc.) for more accurate vulnerability classification.
- **Chain Reaction Scanning**: New logic to automatically escalate from minor tool access to deep exploitation.
- **Improved Tooling**: Rebuilt `detect_tool_execution` with regex patterns for Windows/Linux outputs.
- **Scan Timing**: CLI now reports precise execution duration.

### Fixed
- **HTTP Connector 422 Errors**: Improved handling of Pydantic validation errors in strictly-typed agents like LangChain/FastAPI.
- **Circular Dependencies**: Refactored core modules to use a shared `models.py`.
- **Import Errors**: Fixed legacy import issues for `AgentExecutor` in tests.

### Changed
- Refactored `PromptInjectionScanner` to inherit from `AdaptiveScanner`.
- Updated `igris scan` CLI to support `--ai` and `--provider` flags.

## [0.2.2] - 2026-03-05
- Internal project naming refactor and initial project reorganization.

## [0.1.0] - 2026-03-05
- Initial release.
