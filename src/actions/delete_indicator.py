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
"""Delete a Defender threat indicator by ID."""

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionOutput, OutputField

from ..app import Asset, DeleteIndicatorParams, app
from ..consts import DEFENDERATP_LIST_INDICATORS_ENDPOINT
from ..helper import get_environment_urls, request_json


class DeleteIndicatorOutput(ActionOutput):
    status: str = OutputField(column_name="Status")


@app.action(
    description="Delete an Indicator entity by ID",
    action_type="generic",
    read_only=False,
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'delete-ti-indicator-by-id?view=o365-worldwide" target="_blank">Delete Indicator API Documentation</a>), '
        "rate limitations for this action are 100 calls per minute and 1500 calls per hour."
    ),
)
def delete_indicator(
    params: DeleteIndicatorParams,
    soar: SOARClient,
    asset: Asset,
) -> DeleteIndicatorOutput:
    """Delete the selected indicator and report success."""
    if not params.indicator_id:
        raise ValueError("Missing required parameter: indicator_id")
    _, _, graph_url = get_environment_urls(asset)
    request_json(
        asset,
        "DELETE",
        f"{graph_url}{DEFENDERATP_LIST_INDICATORS_ENDPOINT}/{params.indicator_id}",
    )
    soar.set_message("Successfully deleted indicator entity")
    return DeleteIndicatorOutput(status="success")
