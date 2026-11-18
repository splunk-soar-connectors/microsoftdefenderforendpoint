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
"""Retrieve the organization's Defender exposure score."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, Params, app
from ..consts import DEFENDERATP_EXPOSURE_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetExposureScoreOutput, GetExposureScoreSummary = get_action_output_types(
    "get_exposure_score"
)


@app.action(
    read_only=True,
    description="Retrieve the organizational exposure score",
    action_type="investigate",
    render_as="table",
    summary_type=GetExposureScoreSummary,
)
def get_exposure_score(
    params: Params, soar: SOARClient, asset: Asset
) -> GetExposureScoreOutput:
    """Return the current exposure score and its timestamp."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(asset, "GET", f"{graph_url}{DEFENDERATP_EXPOSURE_ENDPOINT}")
    if not response or response.get("score") is None:
        soar.set_message("No data found")
        return GetExposureScoreOutput()
    score = response["score"]
    soar.set_summary(GetExposureScoreSummary(exposure_score=score))
    return GetExposureScoreOutput.model_validate(response)
