# 🧪 End-to-End Test Suite for Protegrity Developer Edition 0.9.0 using Pytest-BDD

This repository contains end-to-end (E2E) tests written using **pytest** with BDD-style scenarios. All tests are located in the `e2e/` directory.

---

## 🛠️ Prerequisites

Ensure the following are installed on your system:

-   **Platform**: Linux, Windows or MacOS
-   **Python**: Version 3.9 or higher (ensure the executable is available as `python`)
-   **Docker Compose**
-   **Allure**

---

## ⚙️ Setup Instructions

### 📁 Copy Required Files

Copy the `samples` directory and `docker-compose.yml` from the `protegrity-developer-edition` repo to the root of this repo.

1. Navigate to the root directory and install the required dependencies:

```bash
pip install -r requirements.txt
```

2. Run the `docker-compose.yml` file located in the root directory:

```bash
docker compose -f ./docker-compose.yml up -d
```

> **Note:** Automation assumes that Docker Compose is running on `localhost`.  
> If it needs to run on a different machine, add the `"endpoint_url"` key in the `samples/config.json` and `e2e/data/mapping_config.json` files with a valid Discover URL.

3. Generate the `environment.properties` file to capture environment details for the Allure report:

```bash
python tests/e2e/utils/generate_env_details.py
```

---

## 🚀 Running the Tests

From the root directory, run the tests using:

```bash
pytest
```

-   Results are stored in the `allure-results/` directory

---

## 📊 Generating the Allure Report

After running the tests, generate the Allure report with:

```bash
allure generate allure-results -o allure-report --clean
```

-   `--clean`: Clears previous report data before generating a new one

---

## 🌐 Viewing the Allure Report

To open the generated report in your browser:

```bash
allure open allure-report
```
