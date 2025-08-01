import json
import unicodedata


def modify_method_in_config(config_file: str, new_method: str) -> None:
    """
    Modify the 'method' field in a JSON config file to use the new_method.
    """
    # Load the JSON content
    with open(config_file, "r") as file:
        data = json.load(file)

    # Modify the 'method' field
    data["method"] = new_method

    # Write the updated JSON back to the file
    with open(config_file, "w") as file:
        json.dump(data, file, indent=4)

    print(f"Modified config file to use '{new_method}' method.")


def normalize_and_clean(text):
    # Normalize Unicode characters and replace problematic ones
    normalized = unicodedata.normalize("NFKC", text)
    return normalized.replace("\ufffd", "’").replace("’", "'").replace("‘", "'")
