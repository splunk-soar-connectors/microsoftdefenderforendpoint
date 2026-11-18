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
"""Request collection of a Defender device investigation package."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, CollectInvestigationPackageParams, app
from ..consts import DEFENDER_COLLECT_INVESTIGATION_PACKAGE_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


CollectInvestigationPackageOutput, CollectInvestigationPackageSummary = (
    get_action_output_types("collect_investigation_package")
)


@app.action(
    description="Collect an investigation package from a device by its device ID",
    action_type="generic",
    read_only=False,
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/collect-investigation-package" '
        'target="_blank">Collect Investigation Package API Documentation</a>).'
    ),
    summary_type=CollectInvestigationPackageSummary,
)
def collect_investigation_package(
    params: CollectInvestigationPackageParams,
    soar: SOARClient,
    asset: Asset,
) -> CollectInvestigationPackageOutput:
    """Submit the request to collect a package from the selected device."""
    if not params.device_id or not params.comment:
        raise ValueError("Missing required parameters")
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "POST",
        f"{graph_url}{DEFENDER_COLLECT_INVESTIGATION_PACKAGE_ENDPOINT.format(device_id=params.device_id)}",
        json_body={"Comment": params.comment},
    )
    soar.set_summary(
        CollectInvestigationPackageSummary(
            action_taken="Collected Investigation Package"
        )
    )
    return CollectInvestigationPackageOutput.model_validate(response)
