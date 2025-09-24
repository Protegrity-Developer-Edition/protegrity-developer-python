<div align="center">

# Protegrity Developer Edition Python
[![Version](https://img.shields.io/badge/version-1.0.0--rc.2-green.svg?style=flat)](https://github.com/Protegrity-Developer-Edition/protegrity-developer-python/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat)](https://github.com/Protegrity-Developer-Edition/protegrity-developer-python/blob/main/LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg?style=flat)](https://www.python.org/downloads/)
[![Linux](https://img.shields.io/badge/Linux-FCC624?style=flat&logo=linux&logoColor=black)](https://www.linux.org/)
[![Windows](https://img.shields.io/badge/Windows-0078D6?style=flat&logo=windows&logoColor=white)](https://www.microsoft.com/windows/)
[![macOS](https://img.shields.io/badge/mac%20os-000000?style=flat&logo=macos&logoColor=F0F0F0)](https://www.apple.com/macos/)
</div>

Welcome to the `protegrity-developer-python` repository, part of the Protegrity Developer Edition suite. This repository provides the Python module for integrating Protegrity's Data Discovery and Protection APIs into GenAI and traditional applications.
Customize, compile, and use the module as per your requirement.

> **💡Note:** This module should be built and used only if you intend to modify the source code or default behavior.

## Table of Contents

1. [Overview](#overview)
2. [Repository Structure](#repository-structure)
3. [Features](#features)
    - [Protegrity Developer Python](#Protegrity-Developer-Python)
    - [Application Protector Python](#Application-Protector-Python)
4. [Getting Started](#getting-started)
   - [Prerequisites](#prerequisites)
5. [Protegrity Developer Python Module](#protegrity-developer-python-module)
   - [Usage Examples](#usage-examples)
     - [Find and Redact](#find-and-redact)
     - [Find and Protect](#find-and-protect)
     - [Find and Unprotect](#find-and-unprotect)
6. [Application Protector Python module](#application-protector-python-module)
   - [Usage Examples](#usage-examples-1)
     - [Protect & Unprotect [Single Data]](#protect--unprotect-single-data)
     - [Protect & Unprotect [Bulk Data]](#protect--unprotect-bulk-data)
7. [Documentation](#documentation)
8. [Sample Use Case](#sample-use-case)
9. [License](#license)

### Overview

This repository contains two powerful modules designed to handle different aspects of data protection:

- **protegrity_developer_python** - Focuses on data discovery, classification, and redaction of Personally Identifiable Information (PII) in unstructured text
- **appython** - Provides comprehensive data protection and unprotection capabilities for structured data


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
│       └── utils
└── tests
    ├── e2e
    │   ├── features
    │   ├── steps
    │   ├── data
    │   └── utils
    |   └── conftest.py
    │   └── README.md
    └── unit
        ├── appython
        │   ├── bulk
        │   ├── mock
        │   └── single
        └── find_and_secure

```

## Features

### Protegrity Developer Python

| Feature                | Description                                                                                   |
|------------------------|-----------------------------------------------------------------------------------------------|
| **Find and Redact**    | Classifies and redacts Personally Identifiable Information (PII) in unstructured text.        |
| **Find and Protect**   | Classifies and protects Personally Identifiable Information (PII) in unstructured text using Protegrity protection policies.        |
| **Find and Unprotect** | Restores original Personally Identifiable Information (PII) data from its protected form.                                           |
| **Cross-Platform Support** | Compatible with **Linux**, **Windows**, and **MacOS**.                                   |

### Application Protector Python

| Feature                | Description                                                                                   |
|------------------------|-----------------------------------------------------------------------------------------------|
| **Data Protection**    | Protects sensitive structured data using Protegrity policies.                        |
| **Data Unprotection**  | Restores original data from its protected form.                                               |
| **Session Management** | Manages secure sessions for protection and unprotection operations.                           |
| **Cross-Platform Support** | Compatible with **Linux**, **Windows**, and **MacOS**.                                   |

##  Getting Started

### Prerequisites

#### Common Prerequisites
- [Git](https://git-scm.com/downloads)
- [Python >= 3.12.11](https://www.python.org/downloads/)
- [pip](https://pip.pypa.io/en/stable/installation/)
- [Python Virtual Environment](https://packaging.python.org/en/latest/guides/installing-using-pip-and-virtual-environments/) 

### Protegrity Developer Python Prerequisites

No additional prerequisites required beyond the common ones.

### Application Protector Python Prerequisites

- In addition to the common prerequisites, appython requires **API Key, Email, and Password**

   **Obtaining Credentials**

    **Developer Edition Portal Registration**
    - Visit [https://www.protegrity.com/developers/get-api-credentials](https://protegritywpst.wpenginepowered.com/developers/get-api-credentials)
    - Register for a developer account.
    - You will receive an email with your API Key and Password.


### Build the protegrity-developer-python module

1.  Clone the repository. 
    ```
    git clone https://github.com/Protegrity-Developer-Edition/protegrity-developer-python.git
    ```
2.  Navigate to the `protegrity-developer-python`
    > **💡Note:**  Switch to the pre-release-1.0.0 branch `git checkout pre-release-1.0.0`
    
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
- If you already have `protegrity-developer-python` module installed and want to upgrade it, run the following command:

    ```bash
    pip install --upgrade .
    ```
    The installation completes and the success message is displayed.

## Protegrity Developer Python Module
> **💡Note:** Ensure that the Protegrity Developer Edition is running before installing this module.
For setup instructions, please refer to the documentation [here](https://github.com/Protegrity-Developer-Edition/protegrity-developer-edition/blob/main/README.md).
### Usage Examples
#### Find and Redact

```python
import protegrity_developer_python

protegrity_developer_python.configure(
    endpoint_url="http://localhost:8580/pty/data-discovery/v1.0/classify",
    named_entity_map={"PERSON": "NAME", "SOCIAL_SECURITY_NUMBER": "SSN"},
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

```python
import protegrity_developer_python

protegrity_developer_python.configure(
    endpoint_url="http://localhost:8580/pty/data-discovery/v1.0/classify",
    named_entity_map={"PERSON": "NAME", "SOCIAL_SECURITY_NUMBER": "SSN"},
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

```python
import protegrity_developer_python

protegrity_developer_python.configure(
    endpoint_url="http://localhost:8580/pty/data-discovery/v1.0/classify",
    named_entity_map={"PERSON": "NAME", "SOCIAL_SECURITY_NUMBER": "SSN"},
    masking_char="#",
    classification_score_threshold=0.6,
    method="redact",
    enable_logging=True,
    log_level="info"
)

#Pass the output received from find and protect
input_text = "[PERSON]7ro8 lfU'I[/PERSON] SSN is [SOCIAL_SECURITY_NUMBER]616-16-2210[/SOCIAL_SECURITY_NUMBER]."
output_text = protegrity_developer_python.find_and_unprotect(input_text)
print(output_text)
```

## Application Protector Python Module
### Usage Examples
Export your credentials which you have received during [Application Protector Python Prerequisites](#prerequisites)

```bash
export DEV_EDITION_EMAIL='<email_used_for_registration>'
export DEV_EDITION_PASSWORD='<Password_provided_in_email>'
export DEV_EDITION_API_KEY='<API_key_provided_in_email>'
```
#### Protect & Unprotect [Single Data]
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
print("Unprotected Data:%s "%unprotected_data)
```

#### Protect & Unprotect [Bulk Data]
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
print("Unprotected Data:%s "%unprotected_data)

```

> **💡Note:** You **do not** need Protegrity Developer Edition running before executing Application Protector Python Module.

## Documentation

- [Protegrity Developer Edition documentation](http://developer.docs.protegrity.com/)
- For API reference and tutorials, visit [Developer Portal](https://www.protegrity.com/developers)

## Sample Use Case

Use this repo to build GenAI applications like chatbots that:
- Detect Personally Identifiable Information (PII) in prompts using the classifier
- Protect, Redact, or Mask sensitive data before processing
- Protect and Unprotect structured sensitive data

## License

See [LICENSE](https://github.com/Protegrity-Developer-Edition/protegrity-developer-python/blob/main/LICENSE) for terms and conditions.
