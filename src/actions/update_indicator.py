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
"""Update an existing Defender threat indicator."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, UpdateIndicatorParams, app
from ..consts import DEFENDER_UPDATE_INDICATOR_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


UpdateIndicatorOutput, UpdateIndicatorSummary = get_action_output_types(
    "update_indicator"
)


@app.action(
    description="Update an existing Indicator entity",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=UpdateIndicatorSummary,
)
def update_indicator(
    params: UpdateIndicatorParams,
    soar: SOARClient,
    asset: Asset,
) -> list[UpdateIndicatorOutput]:
    """Send an indicator update through the Defender import endpoint."""
    required = (
        params.indicator_value,
        params.indicator_type,
        params.action,
        params.indicator_description,
        params.indicator_title,
    )
    if not all(required):
        raise ValueError("Missing required parameters")
    indicator = {
        "indicatorValue": params.indicator_value,
        "indicatorType": params.indicator_type,
        "action": params.action,
        "description": params.indicator_description,
        "title": params.indicator_title,
    }
    optional = {
        "severity": params.severity,
        "expirationTime": params.expiration_time,
        "application": params.indicator_application,
        "recommendedActions": params.recommended_actions,
        "rbacGroupNames": params.rbac_group_names,
    }
    indicator.update({key: value for key, value in optional.items() if value})

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "POST",
        f"{graph_url}{DEFENDER_UPDATE_INDICATOR_ENDPOINT}",
        json_body={"Indicators": [indicator]},
    )
    results = [
        UpdateIndicatorOutput.model_validate(item) for item in response.get("value", [])
    ]
    soar.set_summary(UpdateIndicatorSummary(action_taken="Updated Indicator"))
    return results
