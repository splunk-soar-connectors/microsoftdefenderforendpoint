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
"""Retrieve alerts associated with a file hash."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetFileAlertsParams, app
from ..consts import DEFENDER_FILE_ALERTS_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


ListAlertsOutput, GetRelatedAlertsSummary = get_action_output_types("get_file_alerts")


@app.action(
    read_only=True,
    description="Retrieve alerts related to a specific file hash",
    action_type="investigate",
    render_as="table",
    verbose="Retrieve alerts related to a specific file hash, such as a SHA1 or SHA256 hash.",
    summary_type=GetRelatedAlertsSummary,
)
def get_file_alerts(
    params: GetFileAlertsParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListAlertsOutput]:
    """Return alerts referencing the supplied file hash."""
    if not params.file_hash:
        raise ValueError("Missing required parameter: file_hash")
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_FILE_ALERTS_ENDPOINT.format(file_hash=params.file_hash)}",
    )
    alerts = response.get("value", [])
    if not alerts:
        soar.set_message("No alerts found for the specified file hash")
        return []
    outputs = []
    for alert in alerts:
        item = dict(alert)
        outputs.append(ListAlertsOutput.model_validate(item))
    soar.set_summary(
        GetRelatedAlertsSummary(
            action_taken="Retrieved Alerts for File", total_results=len(outputs)
        )
    )
    return outputs
