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
"""Retrieve the Microsoft Defender secure score."""

from soar_sdk.abstract import SOARClient
from soar_sdk.action_results import ActionResult

from ..app import Asset, Params, app
from ..consts import DEFENDERATP_SECURE_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetSecureScoreOutput, GetSecureScoreSummary = get_action_output_types(
    "get_secure_score"
)


@app.action(
    read_only=True,
    description="Retrieve your Microsoft Secure Score for devices",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'get-device-secure-score?view=o365-worldwide" target="_blank">Get device secure score API Documentation</a>), '
        "a higher Microsoft Secure Score for devices means endpoints are more resilient to cybersecurity threats."
    ),
    summary_type=GetSecureScoreSummary,
)
def get_secure_score(
    params: Params, soar: SOARClient, asset: Asset
) -> GetSecureScoreOutput:
    """Return the current device secure score and its timestamp."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(asset, "GET", f"{graph_url}{DEFENDERATP_SECURE_ENDPOINT}")
    if not response or response.get("score") is None:
        return ActionResult(status=True, message="No data found")
    score = response["score"]
    soar.set_summary(GetSecureScoreSummary(secure_score=score))
    return GetSecureScoreOutput.model_validate(response)
