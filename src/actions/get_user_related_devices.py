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
"""Find devices associated with a Defender user ID."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetUserDevicesParams, app
from ..consts import DEFENDERATP_USER_FILES_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types
from ..views import render_related_devices


GetFileRelatedDevicesOutput, GetUserRelatedDevicesSummary = get_action_output_types(
    "get_user_related_devices"
)


@app.action(
    name="get user devices",
    read_only=True,
    description="Retrieve a collection of devices related to a given user ID",
    action_type="investigate",
    render_as="table",
    view_handler=render_related_devices,
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'get-user-related-machines?view=o365-worldwide" target="_blank">Get User Related Machines API Documentation</a>), '
        "rate limitations for this action are 100 calls per minute and 1500 calls per hour. The ID is not the full UPN, "
        "but only the user name. (for example, to retrieve machines for user1@contoso.com use user1 for user_id "
        "parameter).<br>The action retrieves data of the last 30 days."
    ),
    summary_type=GetUserRelatedDevicesSummary,
)
def get_user_related_devices(
    params: GetUserDevicesParams,
    soar: SOARClient,
    asset: Asset,
) -> list[GetFileRelatedDevicesOutput]:
    """Return devices associated with the supplied user name."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_USER_FILES_ENDPOINT.format(file_hash=params.user_id)}",
    )
    devices = response.get("value", [])
    if not devices:
        soar.set_message("No devices found")
        return []
    outputs = []
    for device in devices:
        item = dict(device)
        outputs.append(GetFileRelatedDevicesOutput.model_validate(item))
    soar.set_summary(GetUserRelatedDevicesSummary(total_devices=len(outputs)))
    soar.set_message(f"Total devices: {len(outputs)}")
    return outputs
