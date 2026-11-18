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
"""Regression coverage for the local SDK review findings."""

import importlib
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from src.helper import encode_domain

app_module = importlib.import_module("src.app")


class State(dict):
    def __init__(self, values=None, legacy=None):
        super().__init__(values or {})
        self.backend = Mock()
        self.backend.load_state.return_value = legacy or {}


def asset(state=None, limit=2):
    return SimpleNamespace(
        environment="Public",
        start_time=None,
        max_alerts_per_poll=limit,
        ingest_state=state if state is not None else State(),
    )


def params(manual=False):
    return SimpleNamespace(
        is_manual_poll=lambda: manual, container_count=2, start_time=None, end_time=None
    )


def alert(identifier, time="2026-10-29T00:00:00Z"):
    return {
        "id": identifier,
        "lastUpdateTime": time,
        "title": "Alert",
        "severity": "Low",
    }


@pytest.mark.parametrize(
    "value",
    [
        "example.com?x",
        "example.com/stats",
        "https://example.com",
        "a@b.com",
        "example.com#x",
        "../example.com",
        "a.com,b.com",
        "a.com\n",
        "a%2fb.com",
        "a.com\\x",
    ],
)
def test_domain_rejected_before_request(monkeypatch, value):
    for name in (
        "domain_prevalence",
        "get_domain_alerts",
        "get_domain_related_devices",
    ):
        module = importlib.import_module(f"src.actions.{name}")
        request = Mock()
        monkeypatch.setattr(module, "request_json", request)
        handler = getattr(module, name).__wrapped__
        with pytest.raises(ValueError, match="Invalid domain"):
            handler(SimpleNamespace(domain=value, look_back_hours=1), Mock(), asset())
        request.assert_not_called()


@pytest.mark.parametrize("value", ["example.com", "EXAMPLE.com", "host.example.com."])
def test_valid_domain_preserved(value):
    assert encode_domain(value) == value


def test_zero_score_preserved(monkeypatch):
    module = importlib.import_module("src.actions.get_exposure_score")
    monkeypatch.setattr(
        module, "request_json", lambda *args, **kwargs: {"score": 0.0, "time": "now"}
    )
    soar = Mock()
    output = module.get_exposure_score.__wrapped__(None, soar, asset())
    assert output.score == 0.0
    assert soar.set_summary.call_args.args[0].exposure_score == 0.0


@pytest.mark.parametrize("manual", [False, True])
def test_poll_resume_after_preceding_alert_leaves_window(monkeypatch, manual):
    state = State()
    config = asset(state)
    requests = []

    def request(*args, **kwargs):
        query = kwargs["params"]
        requests.append(query)
        assert "$skip" not in query
        if len(requests) == 1:
            return {"value": [alert("A"), alert("B")]}
        # A has since moved outside the window; C and D must still be fetched.
        assert "id gt 'B'" in query["$filter"]
        return {"value": [alert("C"), alert("D")]}

    monkeypatch.setattr(app_module, "request_json", request)
    poll = app_module.on_poll.__wrapped__
    assert [c.source_data_identifier for c in poll(params(manual), Mock(), config)] == [
        "A",
        "B",
    ]
    assert [c.source_data_identifier for c in poll(params(manual), Mock(), config)] == [
        "C",
        "D",
    ]


def test_legacy_checkpoint_migrated_without_tokens(monkeypatch):
    checkpoint = "2026-10-01T00:00:00Z"
    state = State(
        legacy={"last_time": checkpoint, "token": {"refresh_token": "encrypted"}}
    )
    request = Mock(return_value={"value": []})
    monkeypatch.setattr(app_module, "request_json", request)
    list(app_module.on_poll.__wrapped__(params(), Mock(), asset(state)))
    assert (
        "lastUpdateTime ge 2026-10-01T00:00:00.000Z"
        in request.call_args.kwargs["params"]["$filter"]
    )
    assert "token" not in state
    assert "alert_poll_window" not in state


def test_sdk_checkpoint_wins_over_legacy(monkeypatch):
    state = State(
        {"last_modified_time": "2026-10-28T00:00:00Z"},
        legacy={"last_time": "2026-10-01T00:00:00Z"},
    )
    request = Mock(return_value={"value": []})
    monkeypatch.setattr(app_module, "request_json", request)
    list(app_module.on_poll.__wrapped__(params(), Mock(), asset(state)))
    assert (
        "lastUpdateTime ge 2026-10-28T00:00:00.000Z"
        in request.call_args.kwargs["params"]["$filter"]
    )
    state.backend.load_state.assert_not_called()


def test_offset_window_restarted_without_skipping(monkeypatch):
    state = State(
        {
            "alert_poll_window": {
                "start_time": "2026-10-28T00:00:00Z",
                "end_time": "2026-10-29T00:00:00Z",
                "skip": 99,
            }
        }
    )
    request = Mock(return_value={"value": [alert("A")]})
    monkeypatch.setattr(app_module, "request_json", request)
    assert (
        len(list(app_module.on_poll.__wrapped__(params(), Mock(), asset(state)))) == 1
    )
    assert "$skip" not in request.call_args.kwargs["params"]


def test_failed_ingestion_keeps_continuation(monkeypatch):
    state = State()
    monkeypatch.setattr(
        app_module,
        "request_json",
        lambda *args, **kwargs: {"value": [alert("A"), alert("B")]},
    )
    poll = app_module.on_poll.__wrapped__(params(), Mock(), asset(state))
    next(poll)
    poll.close()
    assert not state


def test_zero_limit_does_not_migrate_or_request(monkeypatch):
    state = State(legacy={"last_time": "2026-10-01T00:00:00Z"})
    request = Mock()
    monkeypatch.setattr(app_module, "request_json", request)
    assert (
        list(app_module.on_poll.__wrapped__(params(), Mock(), asset(state, limit=0)))
        == []
    )
    assert not state
    state.backend.load_state.assert_not_called()
    request.assert_not_called()


def test_unset_limit_uses_scheduled_default(monkeypatch):
    request = Mock(return_value={"value": []})
    monkeypatch.setattr(app_module, "request_json", request)
    list(app_module.on_poll.__wrapped__(params(), Mock(), asset(limit=None)))
    assert (
        request.call_args.kwargs["params"]["$top"]
        == app_module.DEFENDER_ALERT_DEFAULT_LIMIT_FOR_SCHEDULE_POLLING
    )


def test_invalid_legacy_checkpoint_fails_before_request(monkeypatch):
    state = State(legacy={"last_time": "invalid"})
    request = Mock()
    monkeypatch.setattr(app_module, "request_json", request)
    with pytest.raises(ValueError, match="legacy last_time"):
        list(app_module.on_poll.__wrapped__(params(), Mock(), asset(state)))
    request.assert_not_called()
    assert not state


@pytest.fixture
def scan_context(monkeypatch):
    module = importlib.import_module("src.actions.scan_device")
    scan_params = module.ScanDeviceParams(
        device_id="a" * 40, scan_type="Quick", comment="Scan device", timeout=10
    )
    monkeypatch.setattr(module.time, "sleep", Mock())
    return module, scan_params, Mock()


@pytest.mark.parametrize("completed_polls", [0, 1])
def test_scan_poll_failure_retains_accepted_event(
    scan_context, monkeypatch, completed_polls
):
    module, scan_params, soar = scan_context
    accepted = {"id": "accepted-event", "status": "Pending"}
    progress = {"id": "accepted-event", "status": "InProgress", "machineId": "a" * 40}
    responses = [
        accepted,
        *([progress] * completed_polls),
        RuntimeError("503 unavailable"),
    ]
    request = Mock(side_effect=responses)
    monkeypatch.setattr(module, "request_json", request)

    result = module.scan_device.__wrapped__(scan_params, soar, asset())

    assert result.get_status() is False
    assert result.get_summary() == {
        "event_id": "accepted-event",
        "scan_status": "InProgress" if completed_polls else "Pending",
    }
    assert result.get_data() == [progress if completed_polls else accepted]
    assert result.get_param() == scan_params.model_dump(exclude_none=True)
    assert "accepted-event" in result.get_message()
    assert "503 unavailable" in result.get_message()
    assert [call.args[1] for call in request.call_args_list] == [
        "POST",
        *(["GET"] * (completed_polls + 1)),
    ]


@pytest.mark.parametrize("response", [{}, {"id": "accepted-event"}])
def test_scan_missing_status_retains_event_and_response(
    scan_context, monkeypatch, response
):
    module, scan_params, soar = scan_context
    monkeypatch.setattr(
        module,
        "request_json",
        Mock(side_effect=[{"id": "accepted-event", "status": "Pending"}, response]),
    )

    result = module.scan_device.__wrapped__(scan_params, soar, asset())

    assert result.get_status() is False
    assert result.get_summary() == {"event_id": "accepted-event"}
    assert result.get_data() == [response]
    assert "did not contain an event status" in result.get_message()


@pytest.mark.parametrize("status", ["Succeeded", "Failed", "InProgress"])
def test_scan_normal_status_results_preserved(scan_context, monkeypatch, status):
    module, scan_params, soar = scan_context
    response = {"id": "accepted-event", "status": status}
    monkeypatch.setattr(
        module,
        "request_json",
        Mock(
            side_effect=[
                {"id": "accepted-event", "status": "Pending"},
                response,
                response,
            ]
        ),
    )

    result = module.scan_device.__wrapped__(scan_params, soar, asset())

    assert result.model_dump(by_alias=True) == response
    assert soar.set_summary.call_args.args[0].model_dump() == {
        "event_id": "accepted-event",
        "scan_status": status,
    }


@pytest.mark.parametrize(
    ("cvss", "name", "expected_filter"),
    [
        (None, None, None),
        (0, None, "cvssV3 eq 0.0"),
        (8, None, "cvssV3 eq 8.0"),
        (8.5, None, "cvssV3 eq 8.5"),
        (0, "O'Brien", "name eq 'O''Brien' and cvssV3 eq 0.0"),
    ],
)
def test_vulnerability_cvss_filter(monkeypatch, cvss, name, expected_filter):
    module = importlib.import_module("src.actions.list_vulnerabilities")
    request = Mock(return_value={"value": []})
    monkeypatch.setattr(module, "request_json", request)
    action_params = module.ListVulnerabilitiesParams(
        cvss=cvss, name_equal=name, limit=10, offset=2
    )

    module.list_vulnerabilities.__wrapped__(action_params, Mock(), asset())

    query = request.call_args.kwargs["params"]
    assert query["$top"] == action_params.limit
    assert query["$skip"] == action_params.offset
    if expected_filter is None:
        assert "$filter" not in query
    else:
        assert query["$filter"] == expected_filter
