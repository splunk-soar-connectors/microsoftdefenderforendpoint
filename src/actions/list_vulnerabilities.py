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
"""List vulnerabilities using filters supported by Defender for Endpoint."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, ListVulnerabilitiesParams, app
from ..consts import (
    DEFENDERATP_VULNERABILITIES_DEFAULT_LIMIT,
    DEFENDERATP_VULNERABILITIES_DEFAULT_OFFSET,
    DEFENDER_LIST_VULNERABILITIES_ENDPOINT,
    NON_NEGATIVE_INTEGER_MSG,
    POSITIVE_INTEGER_MSG,
    VALID_INTEGER_MSG,
)
from ..helper import get_environment_urls, odata_string_literal, request_json
from ..output_models import get_action_output_types


def _integer(value, name: str, *, allow_zero: bool) -> int:
    try:
        number = float(value)
        if not number.is_integer():
            raise ValueError
        result = int(number)
    except (TypeError, ValueError) as error:
        raise ValueError(
            VALID_INTEGER_MSG.format(f"'{name}' action parameter")
        ) from error
    if result < 0:
        raise ValueError(NON_NEGATIVE_INTEGER_MSG.format(f"'{name}' action parameter"))
    if result == 0 and not allow_zero:
        raise ValueError(POSITIVE_INTEGER_MSG.format(f"'{name}' action parameter"))
    return result


ListVulnerabilitiesOutput, ListVulnerabilitiesSummary = get_action_output_types(
    "list_vulnerabilities"
)


@app.action(
    read_only=True,
    description="Retrieve a list of vulnerabilities based on filters",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-all-vulnerabilities" '
        'target="_blank">Get Vulnerabilities API Documentation</a>).'
    ),
    summary_type=ListVulnerabilitiesSummary,
)
def list_vulnerabilities(
    params: ListVulnerabilitiesParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListVulnerabilitiesOutput]:
    """Return vulnerability records matching the supplied filters."""
    limit = _integer(
        params.limit
        if params.limit is not None
        else DEFENDERATP_VULNERABILITIES_DEFAULT_LIMIT,
        "limit",
        allow_zero=False,
    )
    offset = _integer(
        params.offset
        if params.offset is not None
        else DEFENDERATP_VULNERABILITIES_DEFAULT_OFFSET,
        "offset",
        allow_zero=True,
    )
    filters = []
    for value, expression in (
        (params.id, lambda item: f"id eq {odata_string_literal(item)}"),
        (params.name_equal, lambda item: f"name eq {odata_string_literal(item)}"),
        (
            params.name_contains,
            lambda item: f"contains(name, {odata_string_literal(item)})",
        ),
        (
            params.description_contains,
            lambda item: f"contains(description, {odata_string_literal(item)})",
        ),
        (
            params.published_on,
            lambda item: f"publishedOn eq {odata_string_literal(item)}",
        ),
        (params.severity, lambda item: f"severity eq {odata_string_literal(item)}"),
        (params.updated_on, lambda item: f"updatedOn eq {odata_string_literal(item)}"),
    ):
        if value:
            filters.append(expression(value))

    if params.cvss is not None:
        filters.append(f"cvssV3 eq {params.cvss}")

    query_params = {"$top": limit, "$skip": offset}
    if filters:
        query_params["$filter"] = " and ".join(filters)

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_LIST_VULNERABILITIES_ENDPOINT}",
        params=query_params,
    )
    vulnerabilities = response.get("value", [])
    outputs = [
        ListVulnerabilitiesOutput.model_validate(item | {"status": "success"})
        for item in vulnerabilities
    ]
    if not outputs:
        soar.set_message("No vulnerabilities found")
        return outputs

    soar.set_summary(ListVulnerabilitiesSummary(total_vulnerabilities=len(outputs)))
    soar.set_message(f"Total vulnerabilities: {len(outputs)}")
    return outputs
