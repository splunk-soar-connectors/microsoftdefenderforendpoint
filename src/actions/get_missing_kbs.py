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
"""Retrieve security updates missing from a Defender device."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetMissingKbsParams, app
from ..consts import DEFENDERATP_MISSING_KBS_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetMissingKbsOutput, GetMissingKbsSummary = get_action_output_types("get_missing_kbs")


@app.action(
    read_only=True,
    description="Retrieve missing KBs (security updates) by given device ID",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'get-missing-kbs-machine?view=o365-worldwide" target="_blank">Get missing KBs API Documentation</a>), '
        "retrieve the missing security updates for a device."
    ),
    summary_type=GetMissingKbsSummary,
)
def get_missing_kbs(
    params: GetMissingKbsParams,
    soar: SOARClient,
    asset: Asset,
) -> list[GetMissingKbsOutput]:
    """Return the security updates missing from the selected device."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_MISSING_KBS_ENDPOINT.format(device_id=params.device_id)}",
    )
    missing = response.get("value", [])
    if not missing:
        soar.set_message("No missing KBs found for the given device")
        return []
    outputs = [GetMissingKbsOutput.model_validate(item) for item in missing]
    soar.set_summary(GetMissingKbsSummary(total_kbs=len(outputs)))
    return outputs
