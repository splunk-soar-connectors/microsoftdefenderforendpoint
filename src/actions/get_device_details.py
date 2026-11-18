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
"""Retrieve Defender machine records for comma-separated device IDs."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetDeviceDetailsParams, app
from ..consts import DEFENDER_DEVICE_DETAILS_ENDPOINT
from ..helper import failed_action_result, get_environment_urls, request_json
from ..output_models import get_action_output_types


GetDeviceDetailsOutput, GetDeviceDetailsSummary = get_action_output_types(
    "get_device_details"
)


@app.action(
    read_only=True,
    description="Retrieve details for multiple devices by their device IDs",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-machine-by-id" '
        'target="_blank">Get Machine by ID API Documentation</a>).'
    ),
    summary_type=GetDeviceDetailsSummary,
)
def get_device_details(
    params: GetDeviceDetailsParams,
    soar: SOARClient,
    asset: Asset,
) -> list[GetDeviceDetailsOutput]:
    """Fetch each machine record and return the records that exist."""
    if not params.device_ids:
        raise ValueError("Missing required parameter: device_ids")
    device_ids = [
        device_id.strip()
        for device_id in params.device_ids.split(",")
        if device_id.strip()
    ]
    if not device_ids:
        raise ValueError("Missing required parameter: device_ids")

    _, _, graph_url = get_environment_urls(asset)
    outputs = []
    records = []
    for device_id in device_ids:
        try:
            response = request_json(
                asset,
                "GET",
                f"{graph_url}{DEFENDER_DEVICE_DETAILS_ENDPOINT.format(device_id=device_id)}",
                allow_computer_name=True,
            )
            if response:
                records.append(response)
                outputs.append(GetDeviceDetailsOutput.model_validate(response))
        except Exception as error:
            return failed_action_result(
                f"Unable to retrieve device '{device_id}' after {len(outputs)} successful lookup(s): {error}",
                params,
                data=records,
            )
    soar.set_summary(
        GetDeviceDetailsSummary(
            action_taken="Retrieved Device Details", total_results=len(outputs)
        )
    )
    return outputs
