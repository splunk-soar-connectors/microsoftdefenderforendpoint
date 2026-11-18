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
"""Remove application execution restrictions from a Defender device."""

import time

from soar_sdk.abstract import SOARClient

from ..app import Asset, RemoveAppRestrictionParams, app
from ..consts import (
    DEFENDERATP_MACHINEACTIONS_ENDPOINT,
    DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT,
    DEFENDERATP_REMOVE_APP_RESTRICTION_ENDPOINT,
    DEFENDERATP_STATUS_CHECK_DEFAULT,
    DEFENDERATP_STATUS_CHECK_SLEEP,
    DEFENDERATP_STATUS_PENDING,
    DEFENDERATP_STATUS_PROGRESS,
)
from ..helper import failed_action_result, get_environment_urls, request_json
from ..output_models import get_action_output_types


RemoveAppRestrictionOutput, RemoveAppRestrictionSummary = get_action_output_types(
    "remove_app_restriction"
)


@app.action(
    description="Enable execution of any application on the device",
    action_type="contain",
    read_only=False,
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'unrestrict-code-execution?view=o365-worldwide" target="_blank">Remove app restriction API Documentation</a>), '
        "rate limitations are 100 calls per minute and 1500 calls per hour. The action checks status every 5 seconds for "
        "the requested timeout and returns the latest event status and ID if still running. The maximum timeout is 1 minute."
    ),
    summary_type=RemoveAppRestrictionSummary,
)
def remove_app_restriction(
    params: RemoveAppRestrictionParams,
    soar: SOARClient,
    asset: Asset,
) -> RemoveAppRestrictionOutput:
    """Start application unrestriction and poll its machine-action status."""
    raw_timeout = (
        params.timeout
        if params.timeout is not None
        else DEFENDERATP_STATUS_CHECK_DEFAULT
    )
    try:
        numeric_timeout = float(raw_timeout)
        timeout = int(numeric_timeout)
        if numeric_timeout != timeout or timeout <= 0:
            raise ValueError
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Invalid timeout action parameter. Must be a positive integer."
        ) from error
    timeout = min(timeout, DEFENDERATP_QUARANTINE_TIMEOUT_MAX_LIMIT)

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "POST",
        f"{graph_url}{DEFENDERATP_REMOVE_APP_RESTRICTION_ENDPOINT.format(device_id=params.device_id)}",
        json_body={"Comment": params.comment},
    )
    action_id = response.get("id")
    if not action_id:
        raise RuntimeError("Action ID not available. Please try again after sometime")

    latest = response
    try:
        for _ in range(max(1, timeout // DEFENDERATP_STATUS_CHECK_SLEEP)):
            time.sleep(DEFENDERATP_STATUS_CHECK_SLEEP)
            latest = request_json(
                asset,
                "GET",
                f"{graph_url}{DEFENDERATP_MACHINEACTIONS_ENDPOINT.format(action_id=action_id)}",
            )
            if latest.get("status") not in (
                DEFENDERATP_STATUS_PROGRESS,
                DEFENDERATP_STATUS_PENDING,
            ):
                break
    except Exception as error:
        summary = RemoveAppRestrictionSummary(
            event_id=str(action_id), remove_app_restriction_status=latest.get("status")
        )
        return failed_action_result(
            f"Application unrestriction was accepted as event {action_id}, but status polling failed: {error}",
            params,
            data=latest,
            summary=summary,
        )
    data = dict(latest)
    status = data.get("status")
    soar.set_summary(
        RemoveAppRestrictionSummary(
            event_id=str(action_id), remove_app_restriction_status=status
        )
    )
    return RemoveAppRestrictionOutput.model_validate(data)
