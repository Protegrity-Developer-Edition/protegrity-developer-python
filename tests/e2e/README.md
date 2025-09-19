# 🧪 End-to-End Test Suite for Protegrity Developer Python using Pytest-BDD

This repository contains end-to-end (E2E) tests written using **pytest** with BDD-style scenarios. All tests are located in the `e2e/` directory.

---

## 🛠️ Prerequisites

Ensure that you have signed-up for Protegrity Developer Edition and following are installed on your system (Linux/Windows/MacOS):

-   **Python**: Version 3.12 or higher
-   **Docker Compose**
-   **Allure**

---

## ⚙️ Setup Instructions

1. Copy the `samples` directory and `docker-compose.yml` from the `protegrity-developer-edition` repo to the root of this repo `protegrity-developer-python`.

2. Navigate to the root directory and install the required dependencies:

```bash
pip install -r requirements.txt
```

3. Run the `docker-compose.yml` file located in the root directory:

```bash
docker compose up -d
```

> **Note:** Automation assumes that Docker Compose is running on `localhost`.  
> If it needs to run on a different machine, add the `"endpoint_url"` key in the `samples/config.json` and `e2e/data/mapping_config.json` files with a valid Discover URL.
> Example: `"endpoint_url": "http://<IP>:8580/pty/data-discovery/v1.0/classify"`

4. Configure the required environment variables with the credentials received during Protegrity Developer Edition registration: DEV_EDITION_EMAIL, DEV_EDITION_PASSWORD and DEV_EDITION_API_KEY. Set these environment variables using your preferred method, such as `.env` files, `export` commands, system environment settings, or shell configuration files.

5. Generate the `environment.properties` file to capture environment details for the Allure report:

```bash
python tests/e2e/utils/generate_env_details.py
```

---

## 🚀 Running the Tests

From the root directory, run the tests using:

```bash
pytest tests/e2e --disable-warnings
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
