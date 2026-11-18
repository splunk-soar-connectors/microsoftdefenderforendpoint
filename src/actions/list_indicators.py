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
"""Retrieve active threat indicators from Defender for Endpoint."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, ListIndicatorsParams, app
from ..consts import DEFENDERATP_LIST_INDICATORS_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


def _positive_integer(value, parameter_name: str) -> int:
    try:
        number = float(value)
        if not number.is_integer() or number <= 0:
            raise ValueError
        return int(number)
    except (TypeError, ValueError) as error:
        raise ValueError(
            f"'{parameter_name}' action parameter must be a positive integer"
        ) from error


ListIndicatorsOutput, ListIndicatorsSummary = get_action_output_types("list_indicators")


@app.action(
    read_only=True,
    description="Retrieve a collection of all active Indicators",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'get-ti-indicators-collection?view=o365-worldwide" target="_blank">List Indicators API Documentation</a>), '
        "rate limitations for this action are 100 calls per minute and 1500 calls per hour. If the user does not "
        "specify the limit value, it will fetch 100 indicators by default. The maximum value for the limit parameter is 10000."
    ),
    summary_type=ListIndicatorsSummary,
)
def list_indicators(
    params: ListIndicatorsParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListIndicatorsOutput]:
    """Fetch active indicators, optionally applying an OData filter."""
    limit = _positive_integer(
        params.limit if params.limit is not None else 100, "limit"
    )
    if limit > 10000:
        raise ValueError("The maximum value for the limit parameter is 10000")

    _, _, graph_url = get_environment_urls(asset)
    query = {"$top": limit}
    if params.filter:
        query["$filter"] = params.filter
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_LIST_INDICATORS_ENDPOINT}",
        params=query,
    )
    if not response:
        soar.set_message("No data found")
        return []
    indicators = response.get("value", [])
    outputs = []
    for indicator in indicators:
        item = dict(indicator)
        outputs.append(ListIndicatorsOutput.model_validate(item))
    soar.set_summary(ListIndicatorsSummary(total_indicators=len(outputs)))
    soar.set_message(f"Total indicators: {len(outputs)}")
    return outputs
