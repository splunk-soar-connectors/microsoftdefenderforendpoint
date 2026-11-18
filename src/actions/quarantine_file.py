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
"""Quarantine a file on a Microsoft Defender for Endpoint device."""

import time

from soar_sdk.abstract import SOARClient

from ..app import Asset, QuarantineFileParams, app
from ..consts import (
    DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG,
    DEFENDERATP_FILE_QUARANTINE_ENDPOINT,
    DEFENDERATP_MACHINEACTIONS_ENDPOINT,
    DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT,
    DEFENDERATP_STATUS_CHECK_DEFAULT,
    DEFENDERATP_STATUS_CHECK_SLEEP,
    DEFENDERATP_STATUS_PENDING,
    DEFENDERATP_STATUS_PROGRESS,
    NON_NEGATIVE_INTEGER_MSG,
    TIMEOUT_KEY,
    VALID_INTEGER_MSG,
)
from ..helper import failed_action_result, get_environment_urls, request_json
from ..output_models import get_action_output_types


QuarantineFileOutput, QuarantineFileSummary = get_action_output_types("quarantine_file")


@app.action(
    description="Quarantine a file",
    action_type="contain",
    read_only=False,
    render_as="table",
    verbose=(
        "This action can take a while to complete execution. The action retries at an interval of 5 seconds "
        "within a specified <b>timeout</b> to check if event execution is complete. If not, the action would "
        "return the latest status of the event along with the event ID.<br>The <b>get status</b> action can be "
        "used to fetch the latest status of the event with the event ID.<br>The maximum timeout period for a "
        "status check is 10 minutes."
    ),
    summary_type=QuarantineFileSummary,
)
def quarantine_file(
    params: QuarantineFileParams,
    soar: SOARClient,
    asset: Asset,
) -> QuarantineFileOutput:
    """Submit a quarantine request, then poll for its latest status."""
    timeout_value = (
        params.timeout
        if params.timeout is not None
        else DEFENDERATP_STATUS_CHECK_DEFAULT
    )
    try:
        timeout_as_float = float(timeout_value)
        if not timeout_as_float.is_integer():
            raise ValueError
        timeout = int(timeout_as_float)
    except (TypeError, ValueError) as error:
        raise ValueError(VALID_INTEGER_MSG.format(TIMEOUT_KEY)) from error
    if timeout < 0:
        raise ValueError(NON_NEGATIVE_INTEGER_MSG.format(TIMEOUT_KEY))
    timeout = min(timeout, DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT)

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "POST",
        f"{graph_url}{DEFENDERATP_FILE_QUARANTINE_ENDPOINT.format(device_id=params.device_id)}",
        json_body={"Comment": params.comment, "Sha1": params.file_hash},
    )
    action_id = response.get("id")
    if not action_id:
        raise RuntimeError(DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

    status_endpoint = (
        f"{graph_url}{DEFENDERATP_MACHINEACTIONS_ENDPOINT.format(action_id=action_id)}"
    )
    status_response = response
    try:
        for _ in range(
            max(
                1,
                int(
                    max(timeout, DEFENDERATP_STATUS_CHECK_SLEEP)
                    / DEFENDERATP_STATUS_CHECK_SLEEP
                ),
            )
        ):
            time.sleep(DEFENDERATP_STATUS_CHECK_SLEEP)
            status_response = request_json(asset, "GET", status_endpoint)
            if status_response.get("status") not in (
                DEFENDERATP_STATUS_PROGRESS,
                DEFENDERATP_STATUS_PENDING,
            ):
                break
    except Exception as error:
        summary = QuarantineFileSummary(
            event_id=str(action_id), quarantine_status=status_response.get("status")
        )
        return failed_action_result(
            f"File quarantine was accepted as event {action_id}, but status polling failed: {error}",
            params,
            data=status_response,
            summary=summary,
        )

    status = status_response.get("status")
    if not status:
        summary = QuarantineFileSummary(event_id=str(action_id))
        return failed_action_result(
            "File quarantine was accepted, but the status response did not contain an event status",
            params,
            data=status_response,
            summary=summary,
        )
    soar.set_summary(
        QuarantineFileSummary(event_id=action_id, quarantine_status=status)
    )
    soar.set_message(f"Event id: {action_id}, Quarantine status: {status}")

    serialized = dict(status_response)
    return QuarantineFileOutput.model_validate(serialized)
