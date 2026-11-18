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
"""Quarantine a Microsoft Defender for Endpoint device."""

import time

from soar_sdk.abstract import SOARClient

from ..app import Asset, QuarantineDeviceParams
from ..consts import (
    DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG,
    DEFENDERATP_ISOLATE_ENDPOINT,
    DEFENDERATP_MACHINEACTIONS_ENDPOINT,
    DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT,
    DEFENDERATP_STATUS_CHECK_DEFAULT,
    DEFENDERATP_STATUS_CHECK_SLEEP,
    DEFENDERATP_STATUS_PENDING,
    DEFENDERATP_STATUS_PROGRESS,
    TYPE_VALUE_LIST,
)
from ..helper import failed_action_result, get_environment_urls, request_json
from ..output_models import get_action_output_types


QuarantineDeviceOutput, QuarantineDeviceSummary = get_action_output_types(
    "quarantine_device"
)


def quarantine_device(
    params: QuarantineDeviceParams, soar: SOARClient, asset: Asset
) -> QuarantineDeviceOutput:
    """Quarantine a device and return its final or latest action status."""
    if params.type not in TYPE_VALUE_LIST:
        raise ValueError(
            f"Please provide valid input from {TYPE_VALUE_LIST} in 'type' action parameter"
        )
    timeout = (
        params.timeout
        if params.timeout is not None
        else DEFENDERATP_STATUS_CHECK_DEFAULT
    )
    if not float(timeout).is_integer() or timeout <= 0:
        raise ValueError("'timeout' action parameter must be a positive integer")
    timeout = min(int(timeout), DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT)

    _, _, graph_url = get_environment_urls(asset)
    try:
        response = request_json(
            asset,
            "POST",
            f"{graph_url}{DEFENDERATP_ISOLATE_ENDPOINT.format(device_id=params.device_id)}",
            json_body={"Comment": params.comment, "IsolationType": params.type},
        )
    except ValueError as error:
        return failed_action_result(f"Error from server. {error}", params)
    action_id = response.get("id")
    if not action_id:
        raise RuntimeError(DEFENDERATP_ACTION_ID_UNAVAILABLE_MSG)

    status_endpoint = (
        f"{graph_url}{DEFENDERATP_MACHINEACTIONS_ENDPOINT.format(action_id=action_id)}"
    )
    status = response
    try:
        for _ in range(max(1, int(timeout / DEFENDERATP_STATUS_CHECK_SLEEP))):
            time.sleep(DEFENDERATP_STATUS_CHECK_SLEEP)
            status = request_json(asset, "GET", status_endpoint)
            if status.get("status") not in (
                DEFENDERATP_STATUS_PROGRESS,
                DEFENDERATP_STATUS_PENDING,
            ):
                break
    except Exception as error:
        summary = QuarantineDeviceSummary(
            event_id=str(action_id), quarantine_status=status.get("status")
        )
        return failed_action_result(
            f"Quarantine was accepted as event {action_id}, but status polling failed: {error}",
            params,
            data=status,
            summary=summary,
        )
    if not status.get("status"):
        summary = QuarantineDeviceSummary(event_id=str(action_id))
        return failed_action_result(
            "Quarantine was accepted, but the status response did not contain an event status",
            params,
            data=status,
            summary=summary,
        )

    soar.set_summary(
        QuarantineDeviceSummary(
            event_id=str(action_id), quarantine_status=status.get("status")
        )
    )
    return QuarantineDeviceOutput.model_validate(status)
