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
"""Update or create multiple Defender indicators in one request."""

import json

from soar_sdk.abstract import SOARClient

from ..app import Asset, UpdateIndicatorBatchParams, app
from ..consts import DEFENDER_UPDATE_INDICATOR_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


UpdateIndicatorOutput, UpdateIndicatorBatchSummary = get_action_output_types(
    "update_indicator_batch"
)


@app.action(
    description="Update a batch of indicators",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=UpdateIndicatorBatchSummary,
)
def update_indicator_batch(
    params: UpdateIndicatorBatchParams,
    soar: SOARClient,
    asset: Asset,
) -> list[UpdateIndicatorOutput]:
    """Validate the JSON batch and submit it to Defender."""
    if not params.indicator_batch:
        raise ValueError("Missing required parameter: indicator_batch")
    try:
        indicators = json.loads(params.indicator_batch)
    except (TypeError, ValueError) as error:
        raise ValueError(f"Error processing batch: {error}") from error
    if not isinstance(indicators, list) or any(
        not isinstance(item, dict) for item in indicators
    ):
        raise ValueError("indicator_batch must be a list of dictionaries")

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "POST",
        f"{graph_url}{DEFENDER_UPDATE_INDICATOR_ENDPOINT}",
        json_body={"Indicators": indicators},
    )
    results = [
        UpdateIndicatorOutput.model_validate(item) for item in response.get("value", [])
    ]
    soar.set_summary(
        UpdateIndicatorBatchSummary(
            action_taken="Updated batch of indicators", total_results=len(results)
        )
    )
    return results
