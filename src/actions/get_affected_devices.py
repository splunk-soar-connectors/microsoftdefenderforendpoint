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
"""Find machines affected by a CVE."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetAffectedDevicesParams, app
from ..consts import DEFENDER_GET_VULNERABILITY_AFFECTED_DEVICES_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetAffectedDevicesOutput, GetAffectedDevicesSummary = get_action_output_types(
    "get_affected_devices"
)


@app.action(
    read_only=True,
    description="Retrieve a list of devices affected by a vulnerability using CVE IDs",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines-by-vulnerability" '
        'target="_blank">Get Machines by Vulnerability API Documentation</a>).'
    ),
    summary_type=GetAffectedDevicesSummary,
)
def get_affected_devices(
    params: GetAffectedDevicesParams,
    soar: SOARClient,
    asset: Asset,
) -> list[GetAffectedDevicesOutput]:
    """Return devices affected by the supplied CVE identifier."""
    if not params.cve_id:
        raise ValueError("Missing required parameter: cve_id")
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_GET_VULNERABILITY_AFFECTED_DEVICES_ENDPOINT.format(cve_id=params.cve_id)}",
    )
    affected = response.get("value", [])
    outputs = [GetAffectedDevicesOutput.model_validate(item) for item in affected]
    soar.set_summary(
        GetAffectedDevicesSummary(
            action_taken="Retrieved Affected Devices", total_results=len(outputs)
        )
    )
    return outputs
