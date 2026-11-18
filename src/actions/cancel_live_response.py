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
"""Cancel a pending Defender live response action."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, CancelLiveResponseParams, app
from ..consts import DEFENDER_LIVE_RESPONSE_CANCEL_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


CancelLiveResponseOutput, CancelLiveResponseSummary = get_action_output_types(
    "cancel_live_response"
)


@app.action(
    description="Cancel a live response action",
    action_type="generic",
    read_only=False,
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/cancel-machine-action" '
        'target="_blank">Cancel Machine Action API Documentation</a>).'
    ),
    summary_type=CancelLiveResponseSummary,
)
def cancel_live_response(
    params: CancelLiveResponseParams,
    soar: SOARClient,
    asset: Asset,
) -> CancelLiveResponseOutput:
    """Submit the cancellation request and return the machine action."""
    if not params.action_id or not params.comment:
        raise ValueError("Missing required parameters")
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "POST",
        f"{graph_url}{DEFENDER_LIVE_RESPONSE_CANCEL_ENDPOINT.format(action_id=params.action_id)}",
        json_body={"Comment": params.comment},
    )
    soar.set_summary(
        CancelLiveResponseSummary(action_taken="Canceled Live Response Action")
    )
    return CancelLiveResponseOutput.model_validate(response)
