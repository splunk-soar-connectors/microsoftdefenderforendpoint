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
"""Create a Defender for Endpoint alert from an event report."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, CreateAlertParams, app
from ..consts import DEFENDER_CREATE_ALERT_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


CreateAlertOutput, CreateAlertSummary = get_action_output_types("create_alert")


@app.action(
    description="Create a new alert in Defender for Endpoint",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=CreateAlertSummary,
)
def create_alert(
    params: CreateAlertParams,
    soar: SOARClient,
    asset: Asset,
) -> CreateAlertOutput:
    """Create an alert tied to the supplied device and report information."""
    body = {
        "reportId": params.report_id,
        "eventTime": params.event_time,
        "machineId": params.device_id,
        "severity": params.severity,
        "title": params.title,
        "description": params.description,
        "recommendedAction": params.recommended_action,
        "category": params.category,
    }
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "POST",
        f"{graph_url}{DEFENDER_CREATE_ALERT_ENDPOINT}",
        json_body=body,
    )
    response_data = dict(response)
    response_data["action_status"] = "success"
    soar.set_summary(CreateAlertSummary(action_taken="Created Alert"))
    soar.set_message("Action taken: Created Alert")
    return CreateAlertOutput.model_validate(response_data)
