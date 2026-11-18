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
"""Run or retrieve a PowerShell script through Defender live response."""

import json

from soar_sdk.abstract import SOARClient

from ..app import Asset, RunScriptParams
from ..consts import (
    DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG,
    DEFENDERATP_JSON_SCRIPT_NAME,
    DEFENDERATP_LIVE_RESPONSE_DEFAULT,
    DEFENDERATP_LIVE_RESPONSE_ENDPOINT,
    DEFENDERATP_RUN_SCRIPT_COMMAND,
    DEFENDERATP_RUN_SCRIPT_MAX_LIMIT,
    DEFENDERATP_STATUS_FAILED,
    DEFENDERATP_STATUS_SUCCESS,
)
from ..helper import failed_action_result, get_environment_urls, request_json
from ..live_response import (
    fetch_live_response_result,
    poll_machine_action,
    validate_live_response_event,
    validate_timeout,
)
from ..output_models import get_action_output_types


RunScriptOutput, RunScriptSummary = get_action_output_types("run_script_live_response")


def run_script_live_response(
    params: RunScriptParams,
    soar: SOARClient,
    asset: Asset,
) -> list[RunScriptOutput]:
    """Run a script or retrieve the result of a completed RunScript event."""
    required_params = bool(params.script_name and params.device_id and params.comment)
    if not params.event_id and not required_params:
        raise ValueError(
            f"Please provide either event_id or ({DEFENDERATP_JSON_SCRIPT_NAME}, device_id and comment)"
        )

    _, _, graph_url = get_environment_urls(asset)
    summary = RunScriptSummary()
    event_id = params.event_id
    response = {}
    if event_id:
        try:
            response = validate_live_response_event(
                asset, graph_url, event_id, DEFENDERATP_RUN_SCRIPT_COMMAND
            )
        except Exception as error:
            failed_event = getattr(error, "response", None)
            summary.event_id = str(event_id)
            summary.event_id_status = (
                failed_event.get("status")
                if isinstance(failed_event, dict)
                else str(error)
            )
            return failed_action_result(
                f"Unable to validate RunScript event {event_id}: {error}",
                params,
                summary=summary,
            )
        summary.event_id = str(event_id)
        summary.event_id_status = response.get("status")

    if not event_id:
        if not required_params:
            raise ValueError(
                f"Please provide either event_id or ({DEFENDERATP_JSON_SCRIPT_NAME}, device_id and comment)"
            )
        timeout = validate_timeout(
            params.timeout,
            DEFENDERATP_LIVE_RESPONSE_DEFAULT,
            DEFENDERATP_RUN_SCRIPT_MAX_LIMIT,
        )
        command_params = [{"key": "ScriptName", "value": params.script_name}]
        if params.script_args:
            command_params.append({"key": "Args", "value": params.script_args})
        response = request_json(
            asset,
            "POST",
            f"{graph_url}{DEFENDERATP_LIVE_RESPONSE_ENDPOINT.format(device_id=params.device_id)}",
            json_body={
                "Comment": params.comment,
                "Commands": [
                    {"type": DEFENDERATP_RUN_SCRIPT_COMMAND, "params": command_params}
                ],
            },
        )
        event_id = response.get("id")
        if not event_id:
            summary.script_status = DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG
            return failed_action_result(
                DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG, params, summary=summary
            )
        try:
            response = poll_machine_action(asset, graph_url, event_id, timeout)
        except Exception as error:
            summary.event_id = str(event_id)
            summary.script_status = str(error)
            return failed_action_result(
                f"RunScript was accepted as event {event_id}, but status polling failed: {error}",
                params,
                summary=summary,
            )
        summary.event_id = str(event_id)
        summary.script_status = response.get("status")
        if response.get("status") != DEFENDERATP_STATUS_SUCCESS:
            if response.get("status") == DEFENDERATP_STATUS_FAILED:
                return failed_action_result(
                    "Live response RunScript action failed",
                    params,
                    summary=summary,
                )
            soar.set_summary(summary)
            return []

    if response.get("status") != DEFENDERATP_STATUS_SUCCESS:
        return failed_action_result(
            "Live response RunScript action has not succeeded",
            params,
            summary=summary,
        )

    try:
        result_response = fetch_live_response_result(asset, graph_url, event_id)
    except Exception as error:
        message = f"Unable to retrieve live-response result. Error: {error}"
        return failed_action_result(
            message,
            params,
            summary=RunScriptSummary(
                event_id=str(event_id),
                event_id_status=summary.event_id_status,
                script_status=response.get("status"),
                live_response_result=message,
            ),
        )

    try:
        result = result_response.json()
        result = json.loads(json.dumps(result).replace("\\u0000", "\\\\u0000"))
    except Exception as error:
        message = f"Unable to parse live-response result. Error: {error}"
        return failed_action_result(
            message,
            params,
            summary=RunScriptSummary(
                event_id=str(event_id),
                event_id_status=summary.event_id_status,
                script_status=response.get("status"),
                live_response_result=message,
            ),
        )

    summary.event_id = str(event_id)
    summary.script_status = response.get("status")
    soar.set_summary(summary)
    soar.set_message("Successfully executed script")
    return [RunScriptOutput.model_validate(result)]
