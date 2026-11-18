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
"""Run a Microsoft Defender Advanced Hunting query."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, RunQueryParams, app
from ..consts import DEFENDERATP_RUN_QUERY_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


RunQueryOutput, RunQuerySummary = get_action_output_types("run_query")


@app.action(
    read_only=True,
    description="An advanced search query",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'run-advanced-query-api?view=o365-worldwide" target="_blank">Advanced Hunting API Documentation</a>), '
        "rate limitations are 45 calls per minute and 1500 calls per hour. Queries can access the last 30 days of data. "
        "The execution time is limited to 10 minutes per hour and 3 hours per day, with a maximum of 10 minutes for one "
        "request. A single response cannot exceed 124 MB. HTTP 429 indicates a request or CPU quota limit."
    ),
    summary_type=RunQuerySummary,
)
def run_query(
    params: RunQueryParams,
    soar: SOARClient,
    asset: Asset,
) -> list[RunQueryOutput]:
    """Submit the query and return its result rows."""
    if not params.query:
        raise ValueError("Missing required parameter: query")
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "POST",
        f"{graph_url}{DEFENDERATP_RUN_QUERY_ENDPOINT}",
        json_body={"Query": params.query},
    )
    if not response:
        raise RuntimeError("No data found")
    results = response.get("Results", [])
    outputs = [RunQueryOutput(**row) for row in results]
    soar.set_summary(RunQuerySummary(total_results=len(outputs)))
    return outputs
