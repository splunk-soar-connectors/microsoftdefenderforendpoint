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
"""Retrieve a Defender threat indicator by ID."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetIndicatorParams, app
from ..consts import DEFENDER_GET_INDICATOR_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetIndicatorOutput, GetIndicatorSummary = get_action_output_types("get_indicator")


@app.action(
    read_only=True,
    description="Retrieve an Indicator entity by its ID",
    action_type="investigate",
    render_as="table",
    summary_type=GetIndicatorSummary,
)
def get_indicator(
    params: GetIndicatorParams,
    soar: SOARClient,
    asset: Asset,
) -> GetIndicatorOutput:
    """Fetch the selected indicator and summarize the retrieval."""
    if not params.indicator_id:
        raise ValueError("Missing required parameter: indicator_id")
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_GET_INDICATOR_ENDPOINT.format(indicator_id=params.indicator_id)}",
    )
    data = dict(response)
    soar.set_summary(GetIndicatorSummary(action_taken="Retrieved Indicator"))
    return GetIndicatorOutput.model_validate(data)
