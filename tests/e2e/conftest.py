import os
import allure
import pytest
import sys
import importlib
from pytest_bdd import given
from pathlib import Path
from dotenv import load_dotenv
from typing import Any
from appython import Protector
from appython.protector import Session

pytest_plugins = ["steps.common_steps_discover", "steps.common_steps_data_protection"]

# Get the absolute path to the root directory (two levels up from this file)
ROOT_DIR = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def test_configs():
    return {
        "sample_app_find_and_redact": ROOT_DIR / "samples" / "sample-app-find-and-redact.py",
        "sample_app_find_and_protect": ROOT_DIR / "samples" / "sample-app-find-and-protect.py",
        "sample_app_find_and_unprotect": ROOT_DIR / "samples" / "sample-app-find-and-unprotect.py",
        "sample_app_protection": ROOT_DIR / "samples" / "sample-app-protection.py",
        "sample_config_file": ROOT_DIR / "samples" / "config.json",
        "output_file_redact": ROOT_DIR / "samples" / "sample-data" / "output-redact.txt",
        "output_file_protect": ROOT_DIR / "samples" / "sample-data" / "output-protect.txt",
        "output_file_unprotect": ROOT_DIR / "samples" / "sample-data" / "output-unprotect.txt",
        "redact_mask_exp_out_path": ROOT_DIR / "tests" / "e2e" / "data" / "redact_mask_exp_out",
        "find_protect_exp_out_path": ROOT_DIR / "tests" / "e2e" / "data" / "find_protect_exp_out",
        "find_unprot_exp_out": ROOT_DIR / "samples" / "sample-data",
        "user_input_path": ROOT_DIR / "tests" / "e2e" / "data" / "input",
        "mappings_config_file": ROOT_DIR
        / "tests"
        / "e2e"
        / "data"
        / "mapping_config.json",
        "protection_results_path": ROOT_DIR / "tests" / "e2e" / "data" / "protection_results",
        "env_file_path": ROOT_DIR / ".env",
    }


@pytest.fixture(scope="session")
def protegrity_developer_python_env():
    env = os.environ.copy()
    module_path = ROOT_DIR / "src"
    env["PYTHONPATH"] = str(module_path) + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture(scope="session")
def protegrity_developer_python_module(protegrity_developer_python_env):
    module_path = protegrity_developer_python_env["PYTHONPATH"].split(os.pathsep)[0]
    if module_path not in sys.path:
        sys.path.insert(0, module_path)

    return importlib.import_module("protegrity_developer_python")


@pytest.fixture(scope="session")
def protector_instance(test_configs: dict[str]) -> Protector:
    # Load environment variables from .env file
    load_dotenv(dotenv_path=test_configs["env_file_path"])
    try:
        protector = Protector()
        return protector
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


@pytest.fixture(scope="function")
def shared_vars() -> dict[Any]:
    return {
        "user": "superuser",
        "file_line": [],
        "file_header": "",
        "negative_result": {}
    }


@pytest.fixture(scope="function")
def session(shared_vars: dict[Any], protector_instance: Protector) -> Session:
    return protector_instance.create_session(shared_vars["user"])


def pytest_bdd_before_scenario(feature: object):
    allure.dynamic.feature(feature.name)
