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
"""Put a library file on a Defender device through live response."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, PutFileParams, app
from ..consts import (
    DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG,
    DEFENDERATP_LIVE_RESPONSE_DEFAULT,
    DEFENDERATP_LIVE_RESPONSE_ENDPOINT,
    DEFENDERATP_PUT_FILE_COMMAND,
    DEFENDERATP_STATUS_FAILED,
)
from ..helper import failed_action_result, get_environment_urls, request_json
from ..live_response import poll_machine_action, validate_timeout
from ..output_models import get_action_output_types


GetFileLiveResponseOutput, PutFileLiveResponseSummary = get_action_output_types(
    "put_file_live_response"
)


@app.action(
    name="put file",
    description="Put a file from the library to a device using live response",
    action_type="generic",
    read_only=False,
    render_as="table",
    verbose=(
        'Based on the <a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-live-response?view=o365-worldwide" '
        'target="_blank">Run live response commands API Documentation</a>. Live response actions run one at a time; '
        "the action checks status every five seconds until timeout and returns the latest status."
    ),
    summary_type=PutFileLiveResponseSummary,
)
def put_file_live_response(
    params: PutFileParams,
    soar: SOARClient,
    asset: Asset,
) -> GetFileLiveResponseOutput:
    """Start a PutFile command and return its latest machine-action status."""
    if not params.device_id or not params.file_name or not params.comment:
        raise ValueError("Missing required parameters")
    timeout = validate_timeout(params.timeout, DEFENDERATP_LIVE_RESPONSE_DEFAULT)
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "POST",
        f"{graph_url}{DEFENDERATP_LIVE_RESPONSE_ENDPOINT.format(device_id=params.device_id)}",
        json_body={
            "Comment": params.comment,
            "Commands": [
                {
                    "type": DEFENDERATP_PUT_FILE_COMMAND,
                    "params": [{"key": "FileName", "value": params.file_name}],
                }
            ],
        },
    )
    action_id = response.get("id")
    if not action_id:
        raise RuntimeError(DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)
    latest = response
    try:
        latest = poll_machine_action(asset, graph_url, action_id, timeout)
    except Exception as error:
        summary = PutFileLiveResponseSummary(
            event_id=str(action_id), put_file_status=latest.get("status")
        )
        return failed_action_result(
            f"PutFile was accepted as event {action_id}, but status polling failed: {error}",
            params,
            data=latest,
            summary=summary,
        )
    status = latest.get("status")
    summary = PutFileLiveResponseSummary(
        event_id=str(action_id), put_file_status=status
    )
    if status == DEFENDERATP_STATUS_FAILED:
        return failed_action_result(
            "Live response PutFile action failed",
            params,
            data=latest,
            summary=summary,
        )
    soar.set_summary(summary)
    return GetFileLiveResponseOutput.model_validate(latest)
