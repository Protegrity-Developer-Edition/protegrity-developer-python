<div align="center">

# Protegrity AI Developer Edition Python
[![Version](https://img.shields.io/badge/version-1.2.0-green.svg?style=flat)](https://github.com/Protegrity-Developer-Edition/protegrity-ai-developer-python/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat)](https://github.com/Protegrity-Developer-Edition/protegrity-ai-developer-python/blob/main/LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg?style=flat)](https://www.python.org/downloads/)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](https://www.linux.org/)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows&logoColor=white)](https://www.microsoft.com/windows/)
[![macOS](https://img.shields.io/badge/mac%20os-000000?style=flat&logo=macos&logoColor=F0F0F0)](https://www.apple.com/macos/)
[![PyPI 1.2.0](https://img.shields.io/pypi/v/protegrity-ai-developer-python.svg)](https://pypi.org/project/protegrity-ai-developer-python/)
[![Anaconda 1.2.0](https://anaconda.org/protegrity/protegrity-ai-developer-python/badges/version.svg?style=flat)](https://anaconda.org/protegrity/protegrity-ai-developer-python)
[![Service Health](https://img.shields.io/badge/service-health-brightgreen.svg?style=flat&logo=statuspage&logoColor=white)](https://www.protegrity.com/developers/status)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Protegrity-Developer-Edition/protegrity-ai-developer-python)
</div>

Welcome to the `protegrity-ai-developer-python` repository, part of the Protegrity AI Developer Edition suite. This repository provides the Python module for integrating Protegrity's Data Discovery and Protection APIs into GenAI and traditional applications. Customize, compile, and use the module as per your requirements.

> **💡Note:** This module should be built and used only if you intend to modify the source code or default behavior.

## Table of Contents

1. [Overview](#overview)
    - [Why This Matters](#why-this-matters)
2. [Repository Structure](#repository-structure)
3. [Features](#features)
    - [Protegrity Developer Python](#Protegrity-Developer-Python)
    - [Application Protector Python](#Application-Protector-Python)
4. [Getting Started](#getting-started)
   - [Prerequisites](#prerequisites)
5. [Protegrity AI Developer Edition Python Module](#protegrity-ai-developer-edition-python-module)
   - [Usage Examples](#usage-examples)
     - [Find and Redact](#find-and-redact)
     - [Find and Protect](#find-and-protect)
     - [Find and Unprotect](#find-and-unprotect)
6. [Application Protector Python module](#application-protector-python-module)
   - [Usage Examples](#usage-examples-1)
     - [Protect & Unprotect [Single Data]](#protect--unprotect-single-data)
     - [Protect & Unprotect [Bulk Data]](#protect--unprotect-bulk-data)
   - [Connecting to Protegrity AI Team Edition (Cloud Protect)](#connecting-to-protegrity-ai-team-edition-cloud-protect)
   - [Configuration Reference](#configuration-reference)
7. [Migrating from Protegrity AI Developer Edition to Protegrity AI Team Edition](#migrating-from-protegrity-ai-developer-edition-to-protegrity-ai-team-edition)
   - [The `pty-migrate` CLI](#the-pty-migrate-cli)
   - [Usage Statistics](#usage-statistics)
8. [Documentation](#documentation)
9. [Sample Use Case](#sample-use-case)
10. [License](#license)

## Overview

This repository contains two powerful modules designed to handle different aspects of data protection:

- **protegrity_developer_python** - Focuses on data discovery, classification, and redaction of Personally Identifiable Information (PII) in unstructured text.
- **appython** - Provides comprehensive data protection and unprotection capabilities for structured data.

### Why This Matters

Sensitive data shows up in more places than expected, such as logs, payloads, prompts, training sets, and unstructured text. This Python module provides the tools to find and protect that data using tokenization, masking, and discovery, whether the data is in an AI pipeline or a local script. No infrastructure, no UI, just code.

- **Developer-first experience:** Open APIs, sample apps, and modular design make it easy to embed data discovery and protection into any Python project. 

- **Accelerate innovation:** Prototype and validate data discovery and protection strategies in a lightweight, containerized sandbox. 

- **Enable responsible AI:** Protect sensitive information in training data, prompts, and outputs for GenAI and machine learning workflows. 

- **Simplify compliance:** Meet regulatory requirements for data privacy with built-in detection and protection capabilities.

## Repository Structure

```text
├── LICENSE
├── README.md
├── pyproject.toml
├── pytest.ini
├── requirements.txt
├── setup.cfg
├── src
│   ├── appython
│   │   ├── __init__.py
│   │   ├── protector.py
│   │   ├── service   
│   │   └── utils
│   └── protegrity_developer_python
│       ├── __init__.py
│       ├── securefind.py
│       ├── scan.py
│       └── utils
└── tests
    ├── e2e
    │   ├── features
    │   ├── steps
    │   ├── data
    │   ├── utils
    │   ├── conftest.py
    │   └── README.md
    └── unit
        ├── appython
        │   ├── bulk
        │   ├── mock
        │   └── single
        ├── find_and_secure     
        └── semantic_guardrail

```

## Features

### Protegrity Developer Python

| Feature                | Description                                                                                   |
|------------------------|-----------------------------------------------------------------------------------------------|
| **Find and Redact**    | Classifies and redacts PII in unstructured text.        |
| **Find and Protect**   | Classifies and protects PII in unstructured text using Protegrity protection policies.        |
| **Find and Unprotect** | Restores original PII data from its protected form.                                           |
| **Cross-Platform Support** | Compatible with **Linux**, **MacOS**, and **Windows**.                                   |
| **Semantic Guardrail Support** | Scan conversations for PII and risk using Semantic Guardrail API.                     |

### Application Protector Python

| Feature                | Description                                                                                   |
|------------------------|-----------------------------------------------------------------------------------------------|
| **Data Protection**    | Protects sensitive structured data using Protegrity policies.                        |
| **Data Unprotection**  | Restores original data from its protected form.                                               |
| **Session Management** | Manages secure sessions for protection and unprotection operations.                           |
| **Protegrity AI Team Edition support** *(new in 1.2.0)* | Connect to Protegrity AI Team Edition / Cloud Protect endpoints using `PTY_CP_HOST`. |
| **Pluggable authentication** *(new in 1.2.0)* | Five auth modes: `cognito` (Protegrity AI Developer Edition default), `aws_iam` (SigV4), `bearer_token` (static JWT or one fetched using OAuth2 client-credentials), `mtls`, and `none`. Auto-detected from your environment. |
| **HTTP resilience** *(new in 1.2.0)* | Configurable timeouts (`PTY_REQUEST_TIMEOUT`) and automatic retries with exponential backoff on transient failures (`PTY_MAX_RETRIES`). |
| **Local usage statistics** *(new in 1.2.0)* | Anonymous per-operation counts written to `~/.protegrity/stats.json` for migration planning. View with `pty-migrate stats`. |
| **`pty-migrate` CLI** *(new in 1.2.0)* | One-command migration helper: pre-flight checks, PPC policy creation, and stats reporting. |
| **Cross-Platform Support** | Compatible with **Linux**, **MacOS**, and **Windows**.                                   |

##  Getting Started

### Prerequisites

#### Common Prerequisites
- [Git](https://git-scm.com/downloads)
- [Python >= 3.10](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/)
- [Python Virtual Environment](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/) 

### Protegrity Developer Python Prerequisites

No additional prerequisites required beyond the common ones.

### Application Protector Python Prerequisites

`appython` can talk to either Protegrity AI Developer Edition (DE, the hosted cloud sandbox) or Protegrity AI Team Edition (TE, your own Cloud Protect deployment). Pick one of the following, the SDK auto-detects which based on the environment variables it sees.

#### Option A: Protegrity AI Developer Edition (hosted sandbox)
Requires an **API Key**, **Email**, and **Password**.

**Obtaining Credentials**
- Visit [https://www.protegrity.com/developers/dev-edition-api](https://www.protegrity.com/developers/dev-edition-api).
- Register for a developer account.
- Open your inbox to view the email with your API key and password.

#### Option B: Protegrity AI Team Edition / Cloud Protect (own deployment)
Requires the Cloud Protect endpoint URL plus credentials for one of the supported [auth modes](#connecting-to-protegrity-ai-team-edition-cloud-protect).

> No portal registration needed, Protegrity AI Team Edition uses the credentials provided by the Protegrity admin.


### Build the protegrity-ai-developer-python module

1.  Clone the repository. 
    ```
    git clone https://github.com/Protegrity-Developer-Edition/protegrity-ai-developer-python.git
    ```
2.  Navigate to the `protegrity-ai-developer-python` directory.    
3.  Activate the Python virtual environment. 
4.  Install the dependencies.
    ```bash
    pip install -r requirements.txt
    ```
5.  Build and install the module by running the following command from the root directory of the repository.
 - Fresh Installation
    ```bash
    pip install .
    ```
    The installation completes and the success message is displayed.
- If you already have `protegrity-ai-developer-python` module installed and want to upgrade it, run the following command:

    ```bash
    pip install --upgrade .
    ```
    The installation completes and the success message is displayed.

## Protegrity AI Developer Edition Python Module
> **💡Note:** Ensure that the Protegrity AI Developer Edition is set up and running before installing this module.
For setup instructions, refer to the [Protegrity AI Developer Edition readme](https://github.com/Protegrity-Developer-Edition/protegrity-ai-developer-edition/blob/main/README.md) or the [Protegrity AI Developer Edition documentation](https://developer.docs.protegrity.com/).

### Usage Examples

The following examples demonstrate how to use the `protegrity_developer_python` module to discover and handle sensitive data in unstructured text.

#### Find and Redact

Classify sensitive entities in text and replace them with a masking character.

```python
import protegrity_developer_python

protegrity_developer_python.configure(
    endpoint_url="http://localhost:8580/pty/data-discovery/v1.1/classify",
    named_entity_map={"PERSON": "NAME", "SOCIAL_SECURITY_ID": "SSN"},
    masking_char="#",
    classification_score_threshold=0.6,
    method="redact",
    enable_logging=True,
    log_level="info"
)

input_text = "John Doe's SSN is 123-45-6789."
output_text = protegrity_developer_python.find_and_redact(input_text)
print(output_text)
```

#### Find and Protect

Classify sensitive entities in text and protect them using Protegrity tokenization policies.

```python
import protegrity_developer_python

protegrity_developer_python.configure(
    endpoint_url="http://localhost:8580/pty/data-discovery/v1.1/classify",
    named_entity_map={"PERSON": "NAME", "SOCIAL_SECURITY_ID": "SSN"},
    masking_char="#",
    classification_score_threshold=0.6,
    method="redact",
    enable_logging=True,
    log_level="info"
)

input_text = "John Doe's SSN is 123-45-6789."
output_text = protegrity_developer_python.find_and_protect(input_text)
print(output_text)
```

#### Find and Unprotect

Restore previously protected text back to its original form using the tokenized output from `find_and_protect`.

```python
import protegrity_developer_python

protegrity_developer_python.configure(
    endpoint_url="http://localhost:8580/pty/data-discovery/v1.1/classify",
    named_entity_map={"PERSON": "NAME", "SOCIAL_SECURITY_ID": "SSN"},
    masking_char="#",
    classification_score_threshold=0.6,
    method="redact",
    enable_logging=True,
    log_level="info"
)

#Pass the output received from find and protect
input_text = "[PERSON]7ro8 lfU'I[/PERSON] SSN is [SOCIAL_SECURITY_ID]616-16-2210[/SOCIAL_SECURITY_ID]."
output_text = protegrity_developer_python.find_and_unprotect(input_text)
print(output_text)
```

## Application Protector Python Module

The `appython` module provides tokenization-based protection and unprotection for structured data such as credit card numbers, SSNs, and other sensitive fields. It supports both Protegrity AI Developer Edition and Protegrity AI Team Edition endpoints.

### Usage Examples
Export your credentials which you have received during [Application Protector Python Prerequisites](#prerequisites).

```bash
export DEV_EDITION_EMAIL='<email_used_for_registration>'
export DEV_EDITION_PASSWORD='<Password_provided_in_email>'
export DEV_EDITION_API_KEY='<API_key_provided_in_email>'
```
#### Protect & Unprotect [Single Data]

Protect a single value and then restore it using a data element policy.

```python
from appython import Protector

protector = Protector()
user_name = "superuser"
data_element = "ccn"
data = "4111111111111111"

session = protector.create_session(user_name)
protected_data = session.protect(data, data_element)
print("Protected Data: %s" %protected_data)
unprotected_data = session.unprotect(protected_data, data_element)
print("Unprotected Data: %s "%unprotected_data)
```

#### Protect & Unprotect [Bulk Data]

Protect and restore multiple values in a single call. Bulk operations also return per-item error codes.

```python

from appython import Protector

protector = Protector()
user_name = "superuser"
data_element = "ccn"
data = ["5555555555554444", "378282246310005","4111111111111111"]

session = protector.create_session(user_name)
protected_data,error_codes = session.protect(data, data_element)
print("Protected Data: %s" %protected_data)
unprotected_data,error_codes = session.unprotect(protected_data, data_element)
print("Unprotected Data: %s "%unprotected_data)

```

> **💡Note:** You **do not** need Protegrity AI Developer Edition running before executing Application Protector Python Module.

### Connecting to Protegrity AI Team Edition (Cloud Protect)

When you are ready to move off the hosted Protegrity AI Developer Edition sandbox and point the same code at your own Cloud Protect deployment, set `PTY_CP_HOST` and pick an auth mode. The SDK auto-detects the mode from the environment, `PTY_AUTH_MODE` is only required when the detection is ambiguous.

```bash
# 1. Cloud Protect endpoint (required for every Protegrity AI Team Edition mode)
export PTY_CP_HOST=https://<your-cloud-protect-host>/pty

# 2. Pick an auth mode, examples for the two most common cases:

# AWS IAM (SigV4) - default for Cloud Protect behind AWS API Gateway
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1     # or AWS_DEFAULT_REGION

# Bearer token (static or fetched using OAuth2 client credentials)
export PTY_AUTH_MODE=bearer_token
export PTY_STATIC_TOKEN=<your-jwt>
```

Other supported modes: `mtls` (`PTY_CLIENT_CERT` + `PTY_CLIENT_KEY` + optional `PTY_CA_CERT`) and `none` (network-trust deployments such as internal OpenShift routes). For `bearer_token`, the token can either be supplied directly using `PTY_STATIC_TOKEN` or fetched automatically using the OAuth2 client-credentials grant by setting `PTY_TOKEN_ENDPOINT` + `PTY_CLIENT_ID` + `PTY_CLIENT_SECRET`.

After the environment is set, the existing `Protector` / `session.protect()` / `session.unprotect()` code works unchanged.

### Configuration Reference

All settings can be supplied using environment variables, a YAML file at `~/.protegrity/config.yaml` (override path with `PTY_CONFIG_FILE`), or built-in defaults - resolved in that order. A starter template is available at [`config.yaml.template`](config.yaml.template).

```yaml
# ~/.protegrity/config.yaml — keys mirror the PTY_* env vars but lowercased
protect_host: https://cp.example.com/pty
auth_mode: bearer_token
request_timeout: 30
max_retries: 3
# static_token: eyJhbGciOi...   # see security note below
```

> **🔒 Secret keys (`static_token`, `client_secret`) are loaded from the YAML file only if the file is `chmod 600`** (owner read/write only - the same rule `ssh` and `~/.pgpass` enforce). If the file is group-readable or world-readable, secret keys are dropped at load time and a warning is printed to stderr; non-secret keys still load normally. On Windows, the POSIX permission check is skipped.

| Environment variable | Purpose | Default |
|---|---|---|
| `PTY_CP_HOST` | Cloud Protect endpoint URL (Protegrity AI Team Edition). | _none_ |
| `PTY_AUTH_MODE` | Force a specific auth mode: `cognito`, `aws_iam`, `bearer_token`, `mtls`, `none`. | auto-detect |
| `PTY_API_VERSION` | Cloud Protect API version segment. | `1` |
| `PTY_REQUEST_TIMEOUT` | Per-request HTTP timeout in seconds. | `30` |
| `PTY_MAX_RETRIES` | Retries on transient failures (HTTP 429, 5xx, connection errors) with exponential backoff. `0` disables. | `3` |
| `PTY_STATIC_TOKEN` | Bearer token for `bearer_token` mode. | _none_ |
| `PTY_TOKEN_ENDPOINT`, `PTY_CLIENT_ID`, `PTY_CLIENT_SECRET` | OAuth2 client-credentials token fetch for `bearer_token` mode. | _none_ |
| `PTY_CLIENT_CERT`, `PTY_CLIENT_KEY`, `PTY_CA_CERT` | mTLS material. | _none_ |
| `PTY_CONFIG_FILE` | Override the YAML config location. | `~/.protegrity/config.yaml` |
| `DEV_EDITION_EMAIL`, `DEV_EDITION_PASSWORD`, `DEV_EDITION_API_KEY` | Protegrity AI Developer Edition credentials (selects `cognito` mode). | _none_ |

## Migrating from Protegrity AI Developer Edition to Protegrity AI Team Edition

Version 1.2.0 ships a CLI to make the Protegrity AI Developer Edition (DE) → Protegrity AI Team Edition (TE) transition mechanical rather than manual.

### The `pty-migrate` CLI

Installed automatically with the package. 
The following three subcommands are available to help you migrate:

```bash
pty-migrate check          # Pre-flight readiness validation
pty-migrate create-policy  # Create the equivalent DE policy on your PPC
pty-migrate stats          # View local usage statistics
```

- **`pty-migrate check`** validates SDK version, `PTY_CP_HOST`, auth credentials, and (optionally) round-trips a real `protect` call against your Cloud Protect endpoint. Run it once after exporting your env vars; it prints actionable hints for each missing piece.
- **`pty-migrate create-policy`** talks to your Protegrity Provisioned Cluster (PPC) using `PTY_PPC_HOST`, `PTY_PPC_USER`, `PTY_PPC_PASSWORD`, and `PTY_WORKBENCH_PASSWORD`, then creates a TE policy whose data elements match the ones DE provided out of the box (`ccn`, `ssn`, `name`, `email`, ...). It is safe to re-run this command.
- **`pty-migrate stats`** prints a per-data-element, per-day breakdown so you can size your TE deployment based on real DE usage.

> **Storing PPC passwords in the YAML file** is supported but **off by default**. To opt in, add `allow_secrets_in_file: true` to `~/.protegrity/config.yaml` **and** `chmod 600` the file; only then will `ppc_password` and `workbench_password` be read from it. Without both, `pty-migrate` ignores those keys and prints a remediation hint - the same model as `~/.pgpass` and `~/.npmrc`. CLI flags (`--ppc-password`) and env vars (`PTY_PPC_PASSWORD`) always take precedence and need no opt-in.

### Usage Statistics

`appython` writes anonymous local counters (operation type, data element, day) to `~/.protegrity/stats.json` after every `protect`/`unprotect`/`reprotect` call. The file never leaves your machine and contains no payloads or credentials. Disable with `PTY_DISABLE_USAGE_STATS=1`.

> **💡Note:** `PTY_PROTECT_HOST` from earlier 1.2.0 pre-releases was renamed to `PTY_CP_HOST` to avoid confusion with `PTY_PPC_*` (Policy Console) variables. Update any scripts before upgrading.

## Documentation

- [Protegrity AI Developer Edition documentation](http://developer.docs.protegrity.com/)
- For API reference and tutorials, visit [Developer Portal](https://www.protegrity.com/developers)
- For more information about Data Discovery, refer to the [Data Discovery documentation](https://docs.protegrity.com/data-discovery/2.0.0/docs/).
- For more information about Semantic Guardrails, refer to the [Semantic Guardrails documentation](https://docs.protegrity.com/sem_guardrail/1.1.1/docs/).
- For more information about Application Protector Python, refer to the [Application Protector Python documentation](https://docs.protegrity.com/protectors/10.0/docs/ap/ap_python/).

## Sample Use Case

Use this repo to build GenAI applications like chatbots that:
- Detect Personally Identifiable Information (PII) in prompts using the classifier.
- Protect, Redact, or Mask sensitive data before processing.
- Protect and Unprotect structured sensitive data.

## License

See [LICENSE](https://github.com/Protegrity-Developer-Edition/protegrity-ai-developer-python/blob/main/LICENSE) for terms and conditions.
