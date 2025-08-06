import platform
import os


def get_linux_distribution():
    try:
        with open("/etc/os-release", "r") as f:
            lines = f.readlines()
        distro_info = {}
        for line in lines:
            if "=" in line:
                key, value = line.strip().split("=", 1)
                distro_info[key] = value.strip('"')
        name = distro_info.get("NAME", "Unknown")
        version = distro_info.get("VERSION", "Unknown")
        return f"{name} {version}"
    except Exception as e:
        return f"Unknown Linux distribution ({e})"


def get_os_description():
    if platform.system() == "Linux":
        distro = get_linux_distribution()
        kernel_info = platform.uname()
        return f"{distro} | Kernel: {kernel_info.system} {kernel_info.release} ({kernel_info.version})"
    else:
        return f"{platform.system()} {platform.version()}"


# Collect system information
env_properties = {
    "OS": get_os_description(),
    "Python Version": platform.python_version(),
    "Architecture": platform.machine(),
    "Host": platform.node(),
}

# Create or use local allure-results directory
results_dir = "allure-results"
os.makedirs(results_dir, exist_ok=True)

# Write environment.properties file
env_file_path = os.path.join(results_dir, "environment.properties")
with open(env_file_path, "w") as f:
    for key, value in env_properties.items():
        f.write(f"{key}={value}\n")

print(f"✅ environment.properties created at: {env_file_path}")
