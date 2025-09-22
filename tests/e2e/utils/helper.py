import json
from typing import Any
import unicodedata
from datetime import datetime

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

def parse_date(date_str: str):
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%Y.%m.%d", "%Y:%m:%d"):
        try:
            return datetime.strptime(date_str, fmt).date()
        except ValueError:
            continue
    raise ValueError(f"Unknown date format: {date_str}")

def parse_input_data(input_data: str, input_type: str):
    if "list" in input_type:
        input_data = json.loads(input_data)
        if "integer" in input_type:
            input_data = [int(x) for x in input_data]
        elif "bytes" in input_type:
            input_data = [bytes(x, encoding="utf-8") for x in input_data]
        elif "date" in input_type:
            input_data = [parse_date(x) for x in input_data]
        elif "string" in input_type:
            input_data = [x for x in input_data]
        else:
            raise ValueError(f"Unsupported input type: {input_type}")
    elif "tuple" in input_type:
        input_data = tuple(json.loads(input_data))
        if "integer" in input_type:
            input_data = tuple(int(x) for x in input_data)
        elif "bytes" in input_type:
            input_data = tuple(bytes(x, encoding="utf-8") for x in input_data)
        elif "date" in input_type:
            input_data = tuple(parse_date(x) for x in input_data)
        elif "string" in input_type:
            input_data = tuple(x for x in input_data)
        else:
            raise ValueError(f"Unsupported input type: {input_type}")
    elif "integer" in input_type:
        input_data = int(input_data)
    elif "bytes" in input_type:
        input_data = bytes(input_data, encoding="utf-8")
    elif "date" in input_type:	
        input_data = parse_date(input_data)
    elif "string" in input_type:
        input_data = input_data
    else:
        raise ValueError(f"Unsupported input type: {input_type}")
    
    return input_data


def parse_output_data_for_enc(input_data: Any, protected: Any, unprotected: Any, input_type: str):
    if "list" in input_type or "tuple" in input_type:
        if "bytes" in input_type:
            input_data = [x.hex() for x in input_data]
            unprotected = [x.hex() for x in unprotected]
        else:
            input_data = [str(x).encode('utf-8').hex() for x in input_data]
            unprotected = [str(x).encode('utf-8').hex() for x in unprotected]
        protected = [x.hex() for x in protected]
    else:
        if isinstance(input_data, bytes):
            input_data = input_data.hex()
            unprotected = unprotected.hex()
        else:
            input_data = str(input_data).encode('utf-8').hex()
            unprotected = str(unprotected).encode('utf-8').hex()
        protected = protected.hex()

    return input_data, protected, unprotected


def append_result_template(shared_vars, method, input_type, user, data_element, input_data, protected, unprotected):
    """
    Appends result template for standard protection operations to shared_vars["file_line"]. Handles list/tuple/bytes logic.
    """
    template = {
        "method": method,
        "input_type": input_type,
        "user": user,
        "data_element": data_element,
        "input": None,
        "protected": None,
        "unprotected": None
    }
    if "list" in input_type or "tuple" in input_type:
        for input_val, prot, unprot in zip(input_data, protected, unprotected):
            if "bytes" in input_type and method != "encryption":
                input_val = input_val.decode()
                prot = prot.decode()
                unprot = unprot.decode()
            template["input"] = input_val
            template["protected"] = prot
            template["unprotected"] = unprot
            shared_vars["file_line"].append(template.copy())
    else:
        if "bytes" in input_type and method != "encryption":
            input_data = input_data.decode()
            protected = protected.decode()
            unprotected = unprotected.decode()
        template["input"] = input_data
        template["protected"] = protected
        template["unprotected"] = unprotected
        shared_vars["file_line"].append(template.copy())

def append_result_template_eiv(shared_vars, method, input_type, user, data_element, eiv, input_data, protected, protected_iv, unprotected_iv):
    """
    Appends result template for protection operations with external IV to shared_vars["file_line"]. Handles list/tuple/bytes logic.
    """
    template = {
        "method": method,
        "input_type": input_type,
        "user": user,
        "data_element": data_element,
        "external_iv": eiv,
        "input": None,
        "protected": None,
        "protected_iv": None,
        "unprotected_iv": None
    }
    if "list" in input_type or "tuple" in input_type:
        for input_val, prot, prot_iv, unprot_iv in zip(input_data, protected, protected_iv, unprotected_iv):
            if "bytes" in input_type:
                input_val = input_val.decode()
                prot = prot.decode()
                prot_iv = prot_iv.decode()
                unprot_iv = unprot_iv.decode()
            template["input"] = input_val
            template["protected"] = prot
            template["protected_iv"] = prot_iv
            template["unprotected_iv"] = unprot_iv
            shared_vars["file_line"].append(template.copy())
    else:
        if "bytes" in input_type:
            input_data = input_data.decode()
            protected = protected.decode()
            protected_iv = protected_iv.decode()
            unprotected_iv = unprotected_iv.decode()
        template["input"] = input_data
        template["protected"] = protected
        template["protected_iv"] = protected_iv
        template["unprotected_iv"] = unprotected_iv
        shared_vars["file_line"].append(template.copy())

def generate_long_input_data(placeholder: str, data_element: str, input_type: str = None):
    """
    Generate actual long input data for a given placeholder string and data element.
    Supports:
    - 'InputDataMoreThan_<N>_Bytes': returns a string of N+1 bytes
    - 'InputDataMoreThan_<N>_CodePoints': returns a string of N+1 code points
    - For city_de, returns German text of required length
    - If 'Bulk' in placeholder and input_type is 'list' or 'tuple', returns 3 such strings in a list/tuple
    """
    import re, random
    german_letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzäöüÄÖÜß"
    # Match placeholder pattern
    match = re.match(r"InputDataMoreThan_(\d+)_", placeholder)
    def make_one(length):
        if data_element == "city_de":
            return "".join(random.choices(german_letters, k=length))
        elif data_element == "zipcode":
            return "9" * length
        elif data_element == "email":
            return ("a" * 65) + "@example.com" + ("a" * 180)
        elif data_element == "int":
            return "1" * length
        elif data_element == "name":
            return "John" * (length // 4) + "A" * (length % 4)
        elif data_element == "address":
            return ("123 Main St, Springfield " * (length // 24))[:length]
        elif data_element == "ccn":
            return ("4111111122223333" * ((length // 16) + 1))[:length]
        else:
            return "A" * length
    if match:
        length = int(match.group(1)) + 1
        is_bulk = "Bulk" in placeholder and ("list" in input_type or "tuple" in input_type)
        if is_bulk:
            items = [make_one(length) for _ in range(3)]
            return json.dumps(items)
        else:
            return make_one(length)
