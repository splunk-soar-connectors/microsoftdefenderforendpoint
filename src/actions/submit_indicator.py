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
"""Submit or update a threat indicator in Defender for Endpoint."""

import json
from datetime import datetime, UTC

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionResult

from ..app import Asset, SubmitIndicatorParams, app
from ..consts import (
    DEFENDERATP_DATE_FORMAT,
    DEFENDERATP_INVALID_LIST_JSON_ERR,
    DEFENDERATP_INVALID_RBAC_GROUP_NAMES,
    DEFENDERATP_INVALID_SEVERITY,
    DEFENDERATP_INVALID_TIME_ERR,
    DEFENDERATP_LIST_INDICATORS_ENDPOINT,
    DEFENDERATP_PAST_TIME_ERR,
    DEFENDERATP_SUBMIT_INDICATOR_ID_PARSE_ERR,
    DEFENDERATP_SUBMIT_INDICATOR_PARSE_ERR,
    INDICATOR_SEVERITY_LIST,
)
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


SubmitIndicatorOutput, SubmitIndicatorSummary = get_action_output_types(
    "submit_indicator"
)


@app.action(
    description="Submit or Update new Indicator entity",
    action_type="generic",
    read_only=False,
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'post-ti-indicator?view=o365-worldwide" target="_blank">Submit or Update Indicator API Documentation</a>), '
        "rate limitations for this action are 100 calls per minute and 1500 calls per hour. There is a limit of 15,000 "
        "active indicators per tenant.<br><b>Notes:</b><ul><li>For possible parameter values, refer to the documentation "
        "link above.</li><li>CIDR notation for IPs is not supported.</li></ul>"
    ),
    summary_type=SubmitIndicatorSummary,
)
def submit_indicator(
    params: SubmitIndicatorParams,
    soar: SOARClient,
    asset: Asset,
) -> SubmitIndicatorOutput:
    """Validate optional fields and submit a single indicator."""
    expiration_time = params.expiration_time
    if expiration_time:
        try:
            parsed_expiration = datetime.strptime(
                expiration_time, DEFENDERATP_DATE_FORMAT
            ).replace(tzinfo=UTC)
        except ValueError as error:
            raise ValueError(
                DEFENDERATP_INVALID_TIME_ERR.format("expiration time")
            ) from error
        if parsed_expiration <= datetime.now(UTC):
            raise ValueError(DEFENDERATP_PAST_TIME_ERR.format("expiration time"))
        expiration_time = parsed_expiration.strftime(DEFENDERATP_DATE_FORMAT)

    if params.severity and params.severity not in INDICATOR_SEVERITY_LIST:
        raise ValueError(DEFENDERATP_INVALID_SEVERITY)

    rbac_group_names = None
    if params.rbac_group_names:
        try:
            rbac_group_names = json.loads(params.rbac_group_names)
        except (TypeError, ValueError) as error:
            raise ValueError(
                DEFENDERATP_INVALID_LIST_JSON_ERR.format("rbac_group_names")
            ) from error
        if not isinstance(rbac_group_names, list):
            raise ValueError(
                DEFENDERATP_INVALID_LIST_JSON_ERR.format("rbac_group_names")
            )
        rbac_group_names = [name for name in rbac_group_names if name]
        if not rbac_group_names:
            raise ValueError(DEFENDERATP_INVALID_RBAC_GROUP_NAMES)

    payload = {
        "indicatorValue": params.indicator_value,
        "indicatorType": params.indicator_type,
        "title": params.title,
        "action": params.action,
        "description": params.description,
        "generateAlert": params.generate_alert
        if params.generate_alert is not None
        else False,
    }
    optional = {
        "application": params.application,
        "expirationTime": expiration_time,
        "recommendedActions": params.recommended_actions,
        "rbacGroupNames": rbac_group_names,
        "severity": params.severity,
    }
    payload.update({key: value for key, value in optional.items() if value})

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "POST",
        f"{graph_url}{DEFENDERATP_LIST_INDICATORS_ENDPOINT}",
        json_body=payload,
    )
    if not response:
        return ActionResult(status=True, message=DEFENDERATP_SUBMIT_INDICATOR_PARSE_ERR)
    indicator_id = response.get("id")
    if not indicator_id:
        return ActionResult(
            status=True, message=DEFENDERATP_SUBMIT_INDICATOR_ID_PARSE_ERR
        )

    data = dict(response)
    soar.set_summary(SubmitIndicatorSummary(indicator_id=str(indicator_id)))
    return SubmitIndicatorOutput.model_validate(data)
