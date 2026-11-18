# Copyright (c) 2026 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Regression tests for malformed API responses and RunScript failure stages."""

import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from src import helper


@pytest.mark.parametrize("body", ['{"broken":', "<html>Gateway error</html>"])
def test_request_json_rejects_malformed_success(monkeypatch, body):
    response = httpx.Response(200, text=body)
    request = Mock(return_value=response)
    monkeypatch.setattr(helper, "authenticated_request", request)

    with pytest.raises(RuntimeError, match=r"Invalid JSON response.*Status Code: 200"):
        helper.request_json(
            Mock(), "POST", "https://api.securitycenter.windows.com/api/test"
        )

    request.assert_called_once()


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [(200, '{"value": []}', {"value": []}), (200, "", {}), (204, "", {})],
)
def test_request_json_preserves_json_and_empty_success(
    monkeypatch, status, body, expected
):
    monkeypatch.setattr(
        helper,
        "authenticated_request",
        Mock(return_value=httpx.Response(status, text=body)),
    )

    assert (
        helper.request_json(
            Mock(), "GET", "https://api.securitycenter.windows.com/api/test"
        )
        == expected
    )


def test_request_json_preserves_http_error(monkeypatch):
    monkeypatch.setattr(
        helper,
        "authenticated_request",
        Mock(return_value=httpx.Response(403, json={"error": {"message": "Denied"}})),
    )

    with pytest.raises(RuntimeError, match=r"Status Code: 403.*Denied"):
        helper.request_json(
            Mock(), "GET", "https://api.securitycenter.windows.com/api/test"
        )


@pytest.fixture(params=["existing", "new"])
def script_context(monkeypatch, request):
    module = importlib.import_module("src.actions.run_script_live_response")
    event = {"id": "accepted-event", "status": "Succeeded"}
    params = module.RunScriptParams(
        event_id="accepted-event" if request.param == "existing" else None,
        device_id="a" * 40,
        script_name="script.ps1",
        comment="Run script",
    )
    api_request = Mock(return_value={"id": "accepted-event", "status": "Pending"})
    monkeypatch.setattr(module, "request_json", api_request)
    monkeypatch.setattr(module, "poll_machine_action", Mock(return_value=event))
    monkeypatch.setattr(
        module, "validate_live_response_event", Mock(return_value=event)
    )
    return module, params, Mock(), api_request


@pytest.mark.parametrize(
    "error", [httpx.ReadTimeout("timed out"), RuntimeError("HTTP 500")]
)
def test_script_retrieval_failure_keeps_event_and_stage(
    monkeypatch, script_context, error
):
    module, params, soar, api_request = script_context
    monkeypatch.setattr(module, "fetch_live_response_result", Mock(side_effect=error))

    result = module.run_script_live_response(
        params, soar, SimpleNamespace(environment="Public")
    )

    assert result.get_status() is False
    assert "Unable to retrieve live-response result" in result.get_message()
    assert str(error) in result.get_message()
    assert result.get_summary()["event_id"] == "accepted-event"
    assert result.get_summary()["script_status"] == "Succeeded"
    assert result.get_summary()["live_response_result"] == result.get_message()
    assert result.get_param() == params.model_dump(exclude_none=True)
    assert api_request.call_count == (0 if params.event_id else 1)


def test_script_parse_failure_keeps_event_and_stage(monkeypatch, script_context):
    module, params, soar, api_request = script_context
    monkeypatch.setattr(
        module,
        "fetch_live_response_result",
        Mock(return_value=httpx.Response(200, text="not JSON")),
    )

    result = module.run_script_live_response(
        params, soar, SimpleNamespace(environment="Public")
    )

    assert result.get_status() is False
    assert "Unable to parse live-response result" in result.get_message()
    assert result.get_summary()["event_id"] == "accepted-event"
    assert result.get_summary()["script_status"] == "Succeeded"
    assert result.get_summary()["live_response_result"] == result.get_message()
    assert api_request.call_count == (0 if params.event_id else 1)


def test_script_success_preserves_output(monkeypatch, script_context):
    module, params, soar, _ = script_context
    payload = {"script_output": "completed", "script_errors": "", "exit_code": 0}
    monkeypatch.setattr(
        module,
        "fetch_live_response_result",
        Mock(return_value=httpx.Response(200, json=payload)),
    )

    result = module.run_script_live_response(
        params, soar, SimpleNamespace(environment="Public")
    )

    assert [item.model_dump(by_alias=True) for item in result] == [payload]
    summary = soar.set_summary.call_args.args[0]
    assert summary.event_id == "accepted-event"
    assert summary.script_status == "Succeeded"
    soar.set_message.assert_called_once_with("Successfully executed script")
