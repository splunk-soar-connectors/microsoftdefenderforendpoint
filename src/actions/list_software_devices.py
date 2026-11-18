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
"""List devices on which a software package is installed."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, ListSoftwareDevicesParams, app
from ..consts import DEFENDER_LIST_SOFTWARE_DEVICES_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


ListSoftwareDevicesOutput, ListSoftwareDevicesSummary = get_action_output_types(
    "list_software_devices"
)


@app.action(
    read_only=True,
    description="Retrieve a list of devices that have a specific software installed",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines-by-software" '
        'target="_blank">Get Devices With Software Installed API Documentation</a>).'
    ),
    summary_type=ListSoftwareDevicesSummary,
)
def list_software_devices(
    params: ListSoftwareDevicesParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListSoftwareDevicesOutput]:
    """Return devices matching the software ID."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_LIST_SOFTWARE_DEVICES_ENDPOINT.format(software_id=params.id)}",
    )
    devices = response.get("value", [])
    outputs = [
        ListSoftwareDevicesOutput.model_validate(item | {"status": "success"})
        for item in devices
    ]
    if not outputs:
        soar.set_message("No devices found for specified software")
        return outputs

    soar.set_summary(ListSoftwareDevicesSummary(total_devices=len(outputs)))
    soar.set_message(f"Total devices: {len(outputs)}")
    return outputs
