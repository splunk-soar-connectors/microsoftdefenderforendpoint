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
"""Retrieve the status of a Microsoft Defender for Endpoint machine action."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetStatusParams, app
from ..consts import DEFENDERATP_MACHINEACTIONS_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetStatusOutput, GetStatusSummary = get_action_output_types("get_status")


@app.action(
    read_only=True,
    description="Get status of the event on a machine",
    action_type="investigate",
    render_as="table",
    summary_type=GetStatusSummary,
)
def get_status(
    params: GetStatusParams, soar: SOARClient, asset: Asset
) -> GetStatusOutput:
    """Fetch a machine action and summarize its current status."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_MACHINEACTIONS_ENDPOINT.format(action_id=params.event_id)}",
    )
    status = response.get("status")
    if not status:
        raise RuntimeError("The response did not contain an event status")

    soar.set_summary(GetStatusSummary(event_status=status))
    return GetStatusOutput.model_validate(response)
