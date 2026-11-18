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
"""Find devices associated with a file hash."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetFileDevicesParams, app
from ..consts import DEFENDERATP_MACHINE_FILES_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types
from ..views import render_related_devices


GetFileRelatedDevicesOutput, GetFileRelatedDevicesSummary = get_action_output_types(
    "get_file_related_devices"
)


@app.action(
    name="get file devices",
    read_only=True,
    description="Retrieve a collection of devices related to a given file hash (SHA1)",
    action_type="investigate",
    render_as="table",
    view_handler=render_related_devices,
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'get-file-related-machines?view=o365-worldwide" target="_blank">Get File Related Machines API Documentation</a>), '
        "rate limitations for this action are 100 calls per minute and 1500 calls per hour. The valid file identifier "
        "is SHA1.<br>The action retrieves data of the last 30 days."
    ),
    summary_type=GetFileRelatedDevicesSummary,
)
def get_file_related_devices(
    params: GetFileDevicesParams,
    soar: SOARClient,
    asset: Asset,
) -> list[GetFileRelatedDevicesOutput]:
    """Return devices in which Defender observed the file."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_MACHINE_FILES_ENDPOINT.format(file_hash=params.file_hash)}",
    )
    devices = response.get("value", [])
    if not devices:
        soar.set_message("No devices found")
        return []
    outputs = []
    for device in devices:
        item = dict(device)
        outputs.append(GetFileRelatedDevicesOutput.model_validate(item))
    soar.set_summary(GetFileRelatedDevicesSummary(total_devices=len(outputs)))
    soar.set_message(f"Total devices: {len(outputs)}")
    return outputs
