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
"""Retrieve vulnerabilities detected on a Defender device."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetDiscoveredVulnerabilitiesParams, app
from ..consts import DEFENDERATP_VULNERABILITIES_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetDiscoveredVulnerabilitiesOutput, GetDiscoveredVulnerabilitiesSummary = (
    get_action_output_types("get_discovered_vulnerabilities")
)


@app.action(
    read_only=True,
    description="Retrieve a collection of discovered vulnerabilities related to a given device ID",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'get-discovered-vulnerabilities?view=o365-worldwide" target="_blank">Get discovered vulnerabilities API Documentation</a>), '
        "rate limitations for this API are 50 calls per minute and 1500 calls per hour."
    ),
    summary_type=GetDiscoveredVulnerabilitiesSummary,
)
def get_discovered_vulnerabilities(
    params: GetDiscoveredVulnerabilitiesParams,
    soar: SOARClient,
    asset: Asset,
) -> list[GetDiscoveredVulnerabilitiesOutput]:
    """Fetch discovered vulnerabilities for one device."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_VULNERABILITIES_ENDPOINT.format(device_id=params.device_id)}",
    )
    vulnerabilities = response.get("value", [])
    if not vulnerabilities:
        soar.set_message("No vulnerabilities found for the given device")
        return []
    outputs = []
    for vulnerability in vulnerabilities:
        item = dict(vulnerability)
        outputs.append(GetDiscoveredVulnerabilitiesOutput.model_validate(item))
    soar.set_summary(
        GetDiscoveredVulnerabilitiesSummary(total_vulnerabilities=len(outputs))
    )
    return outputs
