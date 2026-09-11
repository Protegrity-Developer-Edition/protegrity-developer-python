from unittest.mock import MagicMock

import pytest

from appython.service.payload_builder import PayloadBuilder
from appython.service.response_handler import ResponseHandler
from appython.utils.output_postprocessor import OutputProcessor


def test_payload_builder_reprotect_and_ivs():
    input_data = {
        "data": ["data1", "data2"],
        "input_datatype": str,
        "charset": "utf-8",
        "is_bulk": True,
        "type": list,
    }
    arguments = {
        "parameters": {
            "user": "alice",
            "data_element": "old_de",
            "new_data_element": "new_de",
            "response_type": str,
            "old_external_iv_str": "iv_old",
            "new_external_iv": "iv_new",
        }
    }
    payload, return_type, base_url = PayloadBuilder.build_api_request(
        input_data, arguments, "reprotect"
    )
    assert payload["old_data_element"] == "old_de"
    assert payload["data_element"] == "new_de"
    assert payload["old_external_iv"] == "iv_old"
    assert payload["external_iv"] == "iv_new"
    assert return_type["is_bulk"] is True


def test_payload_builder_protect_with_external_iv():
    input_data = {
        "data": "single_data",
        "input_datatype": str,
        "charset": "utf-8",
        "is_bulk": False,
        "type": str,
    }
    arguments = {
        "parameters": {
            "user": "alice",
            "data_element": "name",
            "response_type": str,
            "external_iv": "ext_iv_val",
        }
    }
    payload, return_type, base_url = PayloadBuilder.build_api_request(
        input_data, arguments, "protect"
    )
    assert payload["external_iv"] == "ext_iv_val"
    assert payload["data"] == ["single_data"]


def test_payload_builder_enc_validation():
    # ENC with invalid response_type
    input_data = {
        "data": "data",
        "input_datatype": str,
        "charset": "utf-8",
        "is_bulk": False,
        "type": str,
    }
    arguments = {
        "parameters": {
            "user": "alice",
            "data_element": "ENC_DATA",
            "response_type": str,  # not bytes!
        }
    }
    with pytest.raises(Exception, match="26"):
        PayloadBuilder.build_api_request(input_data, arguments, "protect")

    # ENC for unprotect with non-bytes input
    with pytest.raises(Exception, match="26"):
        PayloadBuilder.build_api_request(input_data, arguments, "unprotect")


def test_payload_builder_invalid_cases():
    # invalid is_bulk
    input_data = {
        "data": "data",
        "input_datatype": str,
        "charset": "utf-8",
        "is_bulk": "not_a_bool",
        "type": str,
    }
    arguments = {
        "parameters": {
            "user": "alice",
            "data_element": "name",
            "response_type": str,
        }
    }
    with pytest.raises(Exception):
        PayloadBuilder.build_api_request(input_data, arguments, "protect")

    # invalid operation
    input_data["is_bulk"] = False
    with pytest.raises(Exception):
        PayloadBuilder.build_api_request(input_data, arguments, "invalid_op")


def test_response_handler_error_flows():
    # 200 with success: false
    resp_200_fail = MagicMock(status_code=200)
    resp_200_fail.json.return_value = {
        "success": False,
        "error_msg": "Access Key security groups not found",
    }
    with pytest.raises(Exception) as exc_info:
        ResponseHandler.process(resp_200_fail, {}, "protect")
    assert "ACCESSKEY_NOT_FOUND" in str(exc_info.value)

    # non-200 with error_msg
    resp_non200 = MagicMock(status_code=500)
    resp_non200.json.return_value = {
        "success": False,
        "error_msg": "Application has not been authorized.",
    }
    with pytest.raises(Exception) as exc_info:
        ResponseHandler.process(resp_non200, {}, "protect")
    assert "28" in str(exc_info.value)

    # non-200 without error_msg but message
    resp_non200_msg = MagicMock(status_code=500)
    resp_non200_msg.json.return_value = {
        "success": True,
        "message": "Gateway timeout",
    }
    with pytest.raises(Exception, match="Gateway timeout"):
        ResponseHandler.process(resp_non200_msg, {}, "protect")


def test_response_handler_bulk_tuple_and_exception():
    # 200 bulk tuple
    resp_ok = MagicMock(status_code=200)
    resp_ok.json.return_value = {
        "success": True,
        "results": ["r1", "r2"],
    }
    return_type = {
        "is_bulk": True,
        "type": tuple,
        "response_type": str,
        "isENC": False,
        "charset": None,
    }
    res, codes = ResponseHandler.process(resp_ok, return_type, "protect")
    assert isinstance(res, tuple)
    assert codes == (6, 6)

    # OutputProcessor failure triggers 26
    return_type_bad = {
        "is_bulk": False,
        "type": int,
    }
    resp_bad_data = MagicMock(status_code=200)
    resp_bad_data.json.return_value = {
        "success": True,
        "results": "not_an_int_and_cannot_convert",
    }
    with pytest.raises(Exception, match="26"):
        ResponseHandler.process(resp_bad_data, return_type_bad, "protect")
