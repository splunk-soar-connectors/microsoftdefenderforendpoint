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
"""List vulnerabilities associated with a software inventory entry."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, ListSoftwareVulnerabilitiesParams, app
from ..consts import DEFENDER_LIST_SOFTWARE_VULNERABILITIES_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


ListSoftwareVulnerabilitiesOutput, ListSoftwareVulnerabilitiesSummary = (
    get_action_output_types("list_software_vulnerabilities")
)


@app.action(
    read_only=True,
    description="Retrieve vulnerabilities associated with a specific software",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-vuln-by-software" '
        'target="_blank">Get Vulnerabilities By Software API Documentation</a>).'
    ),
    summary_type=ListSoftwareVulnerabilitiesSummary,
)
def list_software_vulnerabilities(
    params: ListSoftwareVulnerabilitiesParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListSoftwareVulnerabilitiesOutput]:
    """Return vulnerability records for the given software ID."""
    if not params.id:
        raise ValueError("Missing required parameter: id")

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_LIST_SOFTWARE_VULNERABILITIES_ENDPOINT.format(software_id=params.id)}",
    )
    vulnerabilities = response.get("value", [])
    outputs = [
        ListSoftwareVulnerabilitiesOutput.model_validate(item | {"status": "success"})
        for item in vulnerabilities
    ]
    if not outputs:
        soar.set_message("No vulnerabilities found for specified software")
        return outputs

    soar.set_summary(
        ListSoftwareVulnerabilitiesSummary(total_vulnerabilities=len(outputs))
    )
    soar.set_message(f"Total vulnerabilities: {len(outputs)}")
    return outputs
