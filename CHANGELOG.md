# Changelog

All notable changes to the Protegrity Developer Edition Python project will be documented in this file.

## [1.0.0-rc.1] - Current Release

### 🎉 Major New Features

#### New Application Protector Python Module (`appython`)
- **Data Protection & Unprotection**: Complete functionality for protecting and unprotecting sensitive data elements
- **Session Management**: Secure session handling for protection operations
- **Single Data Operations**: Protect and unprotect individual data elements
- **Bulk Data Operations**: Protect and unprotect multiple data elements in batch operations
- **Cloud-based Protection**: Works without requiring local Protegrity Developer Edition installation

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

#### Developer Edition Portal Integration
- **Cloud Authentication**: Integration with Protegrity Developer Edition Portal
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

## [Previous Release] - README1.md Baseline

### Features (Baseline)
- Basic Find and Redact functionality
- Single module structure (`protegrity_developer_python`)
- Python 3.9.23 support
- Basic configuration options
- Simple repository structure

---

*Note: This changelog reflects the transition from the previous single-module approach to the current dual-module architecture with enhanced protection capabilities.*