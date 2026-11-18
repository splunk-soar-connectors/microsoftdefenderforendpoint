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
"""Retrieve the download URI for a Defender investigation package."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetInvestigationUriParams, app
from ..consts import DEFENDER_GET_INVESTIGATION_URI
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetInvestigationUriOutput, GetInvestigationUriSummary = get_action_output_types(
    "get_investigation_uri"
)


@app.action(
    read_only=True,
    description="Retrieve a URI for downloading an investigation package by its action ID",
    action_type="investigate",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-package-sas-uri" '
        'target="_blank">Get Package SAS URI API Documentation</a>).'
    ),
    summary_type=GetInvestigationUriSummary,
)
def get_investigation_uri(
    params: GetInvestigationUriParams,
    soar: SOARClient,
    asset: Asset,
) -> GetInvestigationUriOutput:
    """Fetch the SAS URI for the specified investigation action."""
    if not params.action_id:
        raise ValueError("Missing required parameter: action_id")
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_GET_INVESTIGATION_URI.format(action_id=params.action_id)}",
    )
    soar.set_summary(
        GetInvestigationUriSummary(action_taken="Retrieved Investigation URI")
    )
    return GetInvestigationUriOutput.model_validate(response)
