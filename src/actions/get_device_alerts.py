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
"""Retrieve alerts associated with a Defender device."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetDeviceAlertsParams, app
from ..consts import DEFENDER_DEVICE_ALERTS_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


ListAlertsOutput, GetRelatedAlertsSummary = get_action_output_types("get_device_alerts")


@app.action(
    read_only=True,
    description="Retrieve all alerts related to a specific device",
    action_type="investigate",
    render_as="table",
    summary_type=GetRelatedAlertsSummary,
)
def get_device_alerts(
    params: GetDeviceAlertsParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListAlertsOutput]:
    """Return alerts associated with the supplied device ID."""
    if not params.device_id:
        raise ValueError("Missing required parameter: device_id")
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_DEVICE_ALERTS_ENDPOINT.format(device_id=params.device_id)}",
    )
    alerts = response.get("value", [])
    if not alerts:
        soar.set_message("No alerts found for the specified device")
        return []
    outputs = []
    for alert in alerts:
        item = dict(alert)
        outputs.append(ListAlertsOutput.model_validate(item))
    soar.set_summary(
        GetRelatedAlertsSummary(
            action_taken="Retrieved Alerts for Device", total_results=len(outputs)
        )
    )
    return outputs
