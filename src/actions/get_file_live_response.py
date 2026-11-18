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
"""Download a file from a Defender device through live response."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetFileParams, app
from ..consts import (
    DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG,
    DEFENDERATP_GET_FILE_COMMAND,
    DEFENDERATP_JSON_FILE_PATH,
    DEFENDERATP_LIVE_RESPONSE_DEFAULT,
    DEFENDERATP_LIVE_RESPONSE_ENDPOINT,
    DEFENDERATP_STATUS_FAILED,
    DEFENDERATP_STATUS_SUCCESS,
)
from ..helper import failed_action_result, get_environment_urls, request_json
from ..live_response import (
    add_live_response_file_to_vault,
    download_live_response_result,
    poll_machine_action,
    validate_live_response_event,
    validate_timeout,
)
from ..output_models import get_action_output_types


GetFileLiveResponseOutput, GetFileLiveResponseSummary = get_action_output_types(
    "get_file_live_response"
)


def _to_output(response: dict) -> GetFileLiveResponseOutput:
    data = dict(response)
    return GetFileLiveResponseOutput.model_validate(data)


@app.action(
    name="get file",
    description="Download a file from a device using live response",
    action_type="generic",
    read_only=False,
    render_as="table",
    verbose=(
        'Based on the <a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-live-response?view=o365-worldwide" '
        'target="_blank">Run live response commands API Documentation</a>. Provide event_id to retrieve a completed GetFile action, '
        "or file_path, device_id, and comment to start one. The file is saved to the SOAR vault. Live response actions run one at a time."
    ),
    summary_type=GetFileLiveResponseSummary,
)
def get_file_live_response(
    params: GetFileParams,
    soar: SOARClient,
    asset: Asset,
) -> GetFileLiveResponseOutput:
    """Run or retrieve a GetFile live response command and store its file."""
    required_params = bool(params.file_path and params.device_id and params.comment)
    if not params.event_id and not required_params:
        raise ValueError(
            f"Please provide either event_id or ({DEFENDERATP_JSON_FILE_PATH}, device_id and comment)"
        )

    _, _, graph_url = get_environment_urls(asset)
    summary = GetFileLiveResponseSummary()
    event_id = params.event_id
    response = {}
    if event_id:
        try:
            response = validate_live_response_event(
                asset, graph_url, event_id, DEFENDERATP_GET_FILE_COMMAND
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
                f"Unable to validate GetFile event {event_id}: {error}",
                params,
                summary=summary,
            )
        summary.event_id = str(event_id)
        summary.event_id_status = response.get("status")

    if not event_id:
        if not required_params:
            raise ValueError(
                f"Please provide either event_id or ({DEFENDERATP_JSON_FILE_PATH}, device_id and comment)"
            )
        timeout = validate_timeout(params.timeout, DEFENDERATP_LIVE_RESPONSE_DEFAULT)
        response = request_json(
            asset,
            "POST",
            f"{graph_url}{DEFENDERATP_LIVE_RESPONSE_ENDPOINT.format(device_id=params.device_id)}",
            json_body={
                "Comment": params.comment,
                "Commands": [
                    {
                        "type": DEFENDERATP_GET_FILE_COMMAND,
                        "params": [{"key": "Path", "value": params.file_path}],
                    }
                ],
            },
        )
        event_id = response.get("id")
        if not event_id:
            summary.file_status = DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG
            soar.set_summary(summary)
            raise RuntimeError(DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)
        try:
            response = poll_machine_action(asset, graph_url, event_id, timeout)
        except Exception as error:
            summary.event_id = str(event_id)
            summary.file_status = str(error)
            return failed_action_result(
                f"GetFile was accepted as event {event_id}, but status polling failed: {error}",
                params,
                summary=summary,
            )
        summary.event_id = str(event_id)
        summary.file_status = response.get("status")
        if response.get("status") != DEFENDERATP_STATUS_SUCCESS:
            if response.get("status") == DEFENDERATP_STATUS_FAILED:
                return failed_action_result(
                    "Live response GetFile action failed",
                    params,
                    data=response,
                    summary=summary,
                )
            soar.set_summary(summary)
            return _to_output(response)

    if response.get("status") != DEFENDERATP_STATUS_SUCCESS:
        summary.event_id = str(event_id)
        summary.file_status = response.get("status")
        return failed_action_result(
            "Live response GetFile action has not succeeded",
            params,
            data=response if response else None,
            summary=summary,
        )

    try:
        file_name, content = download_live_response_result(asset, graph_url, event_id)
        vault_id = add_live_response_file_to_vault(soar, file_name, content)
    except Exception as error:
        summary.live_response_result = str(error)
        return failed_action_result(
            f"Unable to retrieve the GetFile result for event {event_id}: {error}",
            params,
            data=response if response else None,
            summary=summary,
        )
    summary.event_id = str(event_id)
    summary.file_status = response.get("status")
    summary.vault_id = str(vault_id)
    soar.set_summary(summary)
    return _to_output(response)
