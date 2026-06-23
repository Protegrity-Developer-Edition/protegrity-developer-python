# Changelog

All notable changes to the Protegrity AI Developer Edition Python project will be documented in this file.

## [1.2.1] - 2026-06-30

This release adds first-class support for connecting `appython` to **Protegrity Team Edition / Cloud Protect**, ships a dedicated migration CLI, and broadens supported Python versions. Existing Developer Edition users see no behavior change — every new feature is opt-in via environment variables or `~/.protegrity/config.yaml`.

### 🎉 Added

#### Team Edition / Cloud Protect connectivity
- **Pluggable authentication providers.** `appython` now supports `cognito` (Developer Edition, default), `aws_iam` (SigV4 against Cloud Protect behind API Gateway), `bearer_token` (static JWT via `PTY_STATIC_TOKEN`, or one fetched via the OAuth2 client-credentials grant), `mtls`, and `none` (network-trust deployments). The provider is auto-detected from the environment; override with `PTY_AUTH_MODE`.
- **Cloud Protect endpoint.** Point the same `Protector` / `session.protect()` / `session.unprotect()` code at your own deployment via `PTY_CP_HOST=https://<your-cloud-protect-host>/pty`.
- **HTTP transport hardening.** New `PTY_REQUEST_TIMEOUT` (default `30s`) and `PTY_MAX_RETRIES` (default `3`, exponential backoff on 429 / 5xx / connection errors; `0` disables) for production resilience.

#### `pty-migrate` CLI (new)
- Installed automatically with the package. Three subcommands to make the DE → TE move mechanical:
  - `pty-migrate check` — pre-flight validation of SDK version, `PTY_CP_HOST`, auth credentials, and (optionally) a real `protect` round-trip against your Cloud Protect endpoint. Cross-checks against the deployed PPC rules so missing data elements or role members surface with a concrete remediation command.
  - `pty-migrate create-policy` — provisions the equivalent Developer Edition policy (data elements, roles, application, rules) on your Protegrity Policy Console. Idempotent — re-runs only create what's missing. Use `--full` to deploy the complete bundled DE policy.
  - `pty-migrate stats` — per-data-element, per-day breakdown of local DE usage so you can size your TE deployment before cutover.

#### Local usage statistics
- Anonymous per-operation counters (operation type, data element, day) are written to `~/.protegrity/stats.json` after every `protect` / `unprotect` / `reprotect` call. No payloads or credentials. Used by `pty-migrate stats` and `pty-migrate check`. Disable with `PTY_DISABLE_USAGE_STATS=1`.

#### YAML configuration file
- All `PTY_*` settings can now live in `~/.protegrity/config.yaml` (override path with `PTY_CONFIG_FILE`). Resolution order: **env var → YAML file → built-in default** for the SDK; **CLI flag → env var → YAML file → default** for `pty-migrate`.
- Starter template at [`config.yaml.template`](config.yaml.template) documents every recognised key.

### 🔄 Changes
- **Python version**: minimum lowered from 3.12.11 to **3.11**, broadening compatibility for developers on Python 3.11 and above.

### 🔐 Security
- **YAML secret-key permission guard.** `static_token` and `client_secret` are read from `~/.protegrity/config.yaml` only when the file is `chmod 600` (pgpass / SSH-style). On loose-permission files the keys are dropped at load time and a warning is printed to stderr; non-secret keys still load. POSIX check is skipped on Windows.
- **Opt-in password-in-file for `pty-migrate`.** `ppc_password` and `workbench_password` are read from the YAML file only when **both** `allow_secrets_in_file: true` is set **and** the file is `chmod 600`. CLI flags and env vars always win and need no opt-in.

### ⚠️ Migration notes
- The `USERNAME` entity is now emitted as `USER_NAME` — update any custom entity maps or downstream consumers that pattern-match on the old name.

---

## [1.1.1] - 2025-12-16

### 📦 Distribution
- **PyPI Package**: Re-released as v1.1.1 to update package metadata and README on PyPI

**Note**: This is a documentation-only release. No code changes from v1.1.0.

---

## [1.1.0] - 2025-12-15

### 🎉 Major New Features

#### Semantic Guardrails v1.1.0 SDK Support
- **Enhanced Risk Scoring**: Updated SDK to support Semantic Guardrails v1.1.0 with improved risk assessment capabilities
- **Vertical-Specific Models**: Added support for Finance and Healthcare industry-specific models
- **Multi-turn Conversation Support**: Enhanced PII scanning and risk scoring across conversation history
- **Improved API Interface**: Streamlined SDK interface for semantic guardrail operations

#### Data Discovery Enhancements
- **Harmonized Classifications**: Support for categorized "harmonized" entity classifications
- **Entity Mapping Updates**: Updated entity-to-data-element mapping to align with Data Discovery v1.1.1
- **Improved Accuracy**: Enhanced classification accuracy and confidence scoring
- **Overlapping Labels**: Fixed ordering logic for overlapping classification labels 

#### Conda Package Support (NEW)
- **Conda Recipe**: Added `conda-recipe/` directory with complete build configuration
- **Cross-Platform Distribution**: Support for conda package distribution across platforms
- **Meta.yaml Configuration**: Comprehensive conda package metadata and dependencies

### 🏗️ Architecture & Structure Changes

#### Repository Structure Enhancements
- **Conda Recipe Directory**: New `conda-recipe/` with build scripts and metadata
- **Enhanced Test Structure**: Improved test organization and expected outputs
- **Configuration Updates**: Removed hardcoded endpoint URLs from `mapping_config.json`

#### SDK Interface Improvements
- **Cleaner APIs**: Simplified method signatures for semantic guardrail operations
- **Better Error Handling**: Enhanced error messages and exception handling
- **Type Hints**: Improved type annotations for better IDE support

### 🔧 Enhanced Configuration & Service Features

#### Configuration Updates
- **Dynamic Endpoint Configuration**: Removed hardcoded `endpoint_url` from mapping configuration
- **Flexible Mapping**: Enhanced entity mapping configuration options
- **Environment-Based Config**: Better support for environment-specific configurations

#### Testing Improvements
- **Updated Test Outputs**: Refreshed expected test outputs to match Data Discovery 1.1.1 entity names and patterns
- **Semantic Guardrails Unit Tests**: Updated unit tests for v1.1.0 compatibility
- **Better Test Coverage**: Expanded test scenarios for new features

### 📚 Documentation & Developer Experience

#### README Enhancements
- **"Why This Matters" Section**: Added context about the importance of data protection
- **Improved Examples**: More comprehensive code examples and use cases
- **Better Prerequisites**: Clearer setup instructions and dependency documentation

#### Developer Guidance
- **Conda Installation**: New installation method via conda packages
- **API Documentation**: Enhanced inline documentation and docstrings
- **Migration Notes**: Guidance for upgrading from 1.0.0 to 1.1.0

### 🔄 Dependencies
- **Updated Requirements**: Refreshed `requirements.txt` with compatible versions
- **Conda Dependencies**: Added conda-specific dependency management
- **Python Version**: Maintained Python 3.12.11+ requirement

### 🔐 Security
- **Dependency Updates**: Updated to latest secure versions of dependencies
- **Vulnerability Fixes**: Applied security patches as needed

### ⚠️ Breaking Changes
- **Configuration Schema**: Removed `endpoint_url` from `mapping_config.json` - endpoints are now dynamically determined
- **Entity Mapping**: Updated entity names and patterns to match Data Discovery 1.1.1 - may require configuration updates for custom mappings

### 📦 Distribution
- **PyPI Package**: Available as `protegrity-developer-python` v1.1.0
- **Conda Package**: New distribution channel via conda (coming soon)
- **Wheel Distribution**: Pre-built wheel available for quick installation

---

## [1.0.0] - 2025-09-30

### 🎉 Major New Features

#### New Application Protector Python Module (`appython`)
- **Data Protection & Unprotection**: Complete functionality for protecting and unprotecting sensitive data elements
- **Session Management**: Secure session handling for protection operations
- **Single Data Operations**: Protect and unprotect individual data elements
- **Bulk Data Operations**: Protect and unprotect multiple data elements in batch operations
- **Cloud-based Protection**: Works without requiring local Protegrity AI Developer Edition installation

#### Enhanced Protegrity Developer Python Module
- **Find and Protect**: New functionality for classifying and protecting PII in unstructured text
- **Find and Unprotect**: New functionality for restoring original PII data from its protected form
- **Enhanced Data Discovery**: Improved classification capabilities

### 🏗️ Architecture & Structure Changes

#### Repository Structure
- **New Module**: Added `src/appython/` directory with comprehensive protection capabilities
  - `protector.py` - Main protection/unprotection logic
  - `service/` - Service layer components
  - `utils/` - Utility functions
- **Enhanced Testing**: Expanded test structure with dedicated paths for both modules
  - `tests/unit/appython/` - Unit tests for Application Protector
  - `tests/unit/find_and_secure/` - Enhanced tests for data discovery
  - Support for bulk operations testing
  - Mock testing capabilities

#### Configuration Files
- **Added**: `setup.cfg` for enhanced build configuration
- **Enhanced**: `pyproject.toml` with support for multiple modules

### 🔧 Prerequisites & Setup

#### New Authentication Requirements
- **API Key, Email, and Password**: Required for Application Protector Python module
- **Developer Portal Registration**: New registration process (in progress)
- **Alternative Signup**: cURL-based signup method for immediate access

#### Updated System Requirements
- **Python Version**: Upgraded minimum requirement from 3.9.23 to 3.12.11
- **Cross-platform Support**: Maintained for Linux, Windows, and macOS

### 📦 Installation & Usage

#### Enhanced Installation Options
- **Fresh Installation**: `pip install .`
- **Upgrade Installation**: `pip install --upgrade .` for existing installations

#### New Usage Patterns
- **Environment Variables**: Support for credential management via environment variables
- **Dual Module Support**: Can use both modules independently or together
- **Session-based Operations**: New session management for Application Protector

### 🔐 Security & Authentication

#### AI Developer Edition Portal Integration
- **Cloud Authentication**: Integration with Protegrity AI Developer Edition Portal
- **API Key Management**: Secure handling of API credentials
- **Registration Process**: Streamlined developer account creation

### 📋 Documentation & Examples

#### Comprehensive Usage Examples
- **Application Protector Examples**: Complete examples for single and bulk data operations
- **Enhanced Data Discovery Examples**: Updated examples with new protect/unprotect capabilities
- **Configuration Guidance**: Detailed setup instructions for both modules

#### Updated Documentation Links
- **Developer Portal**: Enhanced documentation and API reference
- **Setup Instructions**: Clear guidance for different use cases

### 🎯 Use Cases

#### Expanded Application Scenarios
- **GenAI Applications**: Enhanced support for AI/ML applications
- **Structured Data Protection**: New capabilities for protecting structured data elements
- **Unstructured Text Processing**: Improved PII detection and protection in text
- **Hybrid Workflows**: Support for both redaction and protection workflows

### ⚠️ Breaking Changes
- **Python Version**: Minimum Python version increased from 3.9.23 to 3.12.11

### 🐛 Bug Fixes & Improvements
- **Enhanced Error Handling**: Better error codes and handling for bulk operations
- **Improved Logging**: Enhanced logging capabilities across both modules
- **Cross-platform Stability**: Improved compatibility across different operating systems

---

## [Previous Release] - README.md Baseline

### Features (Baseline)
- Basic Find and Redact functionality
- Single module structure (`protegrity_developer_python`)
- Python 3.9.23 support
- Basic configuration options
- Simple repository structure
