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
"""List version distribution for a Defender for Endpoint software entry."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, ListSoftwareVersionsParams, app
from ..consts import DEFENDER_LIST_SOFTWARE_VERSIONS_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


ListSoftwareVersionsOutput, ListSoftwareVersionsSummary = get_action_output_types(
    "list_software_versions"
)


@app.action(
    read_only=True,
    description="Retrieve a list of organization's software version distribution",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-software-ver-distribution" '
        'target="_blank">Get Software Distribution API Documentation</a>).'
    ),
    summary_type=ListSoftwareVersionsSummary,
)
def list_software_versions(
    params: ListSoftwareVersionsParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListSoftwareVersionsOutput]:
    """Return distribution counts grouped by software version."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_LIST_SOFTWARE_VERSIONS_ENDPOINT.format(software_id=params.id)}",
    )
    versions = response.get("value", [])
    outputs = [
        ListSoftwareVersionsOutput.model_validate(item | {"status": "success"})
        for item in versions
    ]
    if not outputs:
        soar.set_message("No software versions found for specified software")
        return outputs

    soar.set_summary(ListSoftwareVersionsSummary(total_versions=len(outputs)))
    soar.set_message(f"Total versions: {len(outputs)}")
    return outputs
