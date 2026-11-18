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
"""Retrieve software installed on a Defender device."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetInstalledSoftwareParams, app
from ..consts import DEFENDERATP_INSTALLED_SOFTWARE_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetInstalledSoftwareOutput, GetInstalledSoftwareSummary = get_action_output_types(
    "get_installed_software"
)


@app.action(
    read_only=True,
    description="Retrieve a collection of installed software related to a given device ID",
    action_type="investigate",
    render_as="table",
    summary_type=GetInstalledSoftwareSummary,
)
def get_installed_software(
    params: GetInstalledSoftwareParams,
    soar: SOARClient,
    asset: Asset,
) -> list[GetInstalledSoftwareOutput]:
    """Return software inventory reported for the selected device."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_INSTALLED_SOFTWARE_ENDPOINT.format(device_id=params.device_id)}",
    )
    software = response.get("value", [])
    if not software:
        soar.set_message("No software found for the given device")
        return []
    outputs = [GetInstalledSoftwareOutput.model_validate(item) for item in software]
    soar.set_summary(GetInstalledSoftwareSummary(total_software=len(outputs)))
    soar.set_message(f"Total software: {len(outputs)}")
    return outputs
