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
"""Unquarantine a Microsoft Defender for Endpoint device."""

import time

from soar_sdk.abstract import SOARClient
from soar_sdk.params import Param, Params

from ..app import Asset, app
from ..consts import (
    DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG,
    DEFENDERATP_MACHINEACTIONS_ENDPOINT,
    DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT,
    DEFENDERATP_STATUS_CHECK_DEFAULT,
    DEFENDERATP_STATUS_CHECK_SLEEP,
    DEFENDERATP_STATUS_PENDING,
    DEFENDERATP_STATUS_PROGRESS,
    DEFENDERATP_UNISOLATE_ENDPOINT,
)
from ..helper import failed_action_result, get_environment_urls, request_json
from ..output_models import get_action_output_types


class UnquarantineDeviceParams(Params):
    device_id: str = Param(
        description="ID of the device to unquarantine",
        primary=True,
        cef_types=["defender atp device id"],
        column_name="Device ID",
    )
    comment: str = Param(description="Comment for unquarantine", column_name="Comment")
    timeout: int | None = Param(
        description="Timeout in seconds (Default: 30)", default=30
    )


UnquarantineDeviceOutput, UnquarantineDeviceSummary = get_action_output_types(
    "unquarantine_device"
)


@app.action(
    description="Unquarantine the device",
    action_type="correct",
    read_only=False,
    render_as="table",
    verbose=(
        "This action can take a while to complete execution. The action retries at an interval of 5 seconds "
        "within a specified <b>timeout</b> to check if event execution is complete. If not, the action would "
        "return the latest status of the event along with the event ID.<br>The <b>get status</b> action can be "
        "used to fetch the latest status of the event with the event ID.<br>The maximum timeout period for a "
        "status check is 10 minutes."
    ),
    summary_type=UnquarantineDeviceSummary,
)
def unquarantine_device(
    params: UnquarantineDeviceParams,
    soar: SOARClient,
    asset: Asset,
) -> UnquarantineDeviceOutput:
    """Remove device isolation and return the latest action status."""
    timeout = (
        params.timeout
        if params.timeout is not None
        else DEFENDERATP_STATUS_CHECK_DEFAULT
    )
    if timeout <= 0:
        raise ValueError("'timeout' action parameter must be a positive integer")
    timeout = min(timeout, DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT)

    _, _, graph_url = get_environment_urls(asset)
    try:
        response = request_json(
            asset,
            "POST",
            f"{graph_url}{DEFENDERATP_UNISOLATE_ENDPOINT.format(device_id=params.device_id)}",
            json_body={"Comment": params.comment},
        )
    except ValueError as error:
        return failed_action_result(f"Error from server. {error}", params)
    action_id = response.get("id")
    if not action_id:
        raise RuntimeError(DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

    status_endpoint = (
        f"{graph_url}{DEFENDERATP_MACHINEACTIONS_ENDPOINT.format(action_id=action_id)}"
    )
    response_status = response
    try:
        for _ in range(max(1, int(timeout / DEFENDERATP_STATUS_CHECK_SLEEP))):
            time.sleep(DEFENDERATP_STATUS_CHECK_SLEEP)
            response_status = request_json(asset, "GET", status_endpoint)
            if response_status.get("status") not in (
                DEFENDERATP_STATUS_PROGRESS,
                DEFENDERATP_STATUS_PENDING,
            ):
                break
    except Exception as error:
        summary = UnquarantineDeviceSummary(
            event_id=str(action_id), unquarantine_status=response_status.get("status")
        )
        return failed_action_result(
            f"Unquarantine was accepted as event {action_id}, but status polling failed: {error}",
            params,
            data=response_status,
            summary=summary,
        )

    status = response_status.get("status")
    if not status:
        summary = UnquarantineDeviceSummary(event_id=str(action_id))
        return failed_action_result(
            "Unquarantine was accepted, but the status response did not contain an event status",
            params,
            data=response_status,
            summary=summary,
        )
    soar.set_summary(
        UnquarantineDeviceSummary(event_id=action_id, unquarantine_status=status)
    )
    soar.set_message(f"Event id: {action_id}, Unquarantine status: {status}")
    return UnquarantineDeviceOutput(**response_status)
