import os
import allure
import pytest
import sys
import importlib
from pytest_bdd import given
from pathlib import Path

# Get the absolute path to the root directory (two levels up from this file)
ROOT_DIR = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def test_configs():
    return {
        "app_file": ROOT_DIR / "samples" / "sample-app-find-and-redact.py",
        "sample_config_file": ROOT_DIR / "samples" / "config.json",
        "output_file": ROOT_DIR / "samples" / "sample-data" / "output.txt",
        "expected_output_path": ROOT_DIR / "tests" / "e2e" / "data" / "expected_output",
        "user_input_path": ROOT_DIR / "tests" / "e2e" / "data" / "input",
        "mappings_config_file": ROOT_DIR
        / "tests"
        / "e2e"
        / "data"
        / "mapping_config.json",
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


@given("python version 3.9 or higher is installed")
@given("protegrity_developer_python module is present")
@given("sample application is present")
@given("config.json is present")
@given("a sample input file containing PII data")
@given("docker-compose.yml is up and running")
def do_nothing():
    pass


def pytest_bdd_before_scenario(feature):
    allure.dynamic.feature(feature.name)
