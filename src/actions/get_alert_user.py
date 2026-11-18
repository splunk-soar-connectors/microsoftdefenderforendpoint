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
"""Retrieve the assigned user associated with a Defender alert."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetAlertUserParams, app
from ..consts import DEFENDERATP_ALERTS_ID_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetAlertUserOutput, GetAlertUserSummary = get_action_output_types("get_alert_user")


@app.action(
    read_only=True,
    description="Retrieve user for specific Alert from its ID",
    action_type="investigate",
    render_as="table",
    summary_type=GetAlertUserSummary,
)
def get_alert_user(
    params: GetAlertUserParams,
    soar: SOARClient,
    asset: Asset,
) -> GetAlertUserOutput:
    """Return the account record attached to the alert."""
    if not params.alert_id:
        raise ValueError("Missing required parameter: alert_id")

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_ALERTS_ID_ENDPOINT.format(input=params.alert_id)}/user",
    )
    response_data = dict(response)
    soar.set_summary(
        GetAlertUserSummary(action_taken="Retrieved Assigned User for Alert")
    )
    soar.set_message("Action taken: Retrieved Assigned User for Alert")
    return GetAlertUserOutput.model_validate(response_data | {"status": "success"})
