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
"""List vulnerabilities affecting devices or software in the organization."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, ListDeviceVulnerabilitiesParams, app
from ..consts import (
    DEFENDERATP_DEVICE_VULNERABILITIES_DEFAULT_LIMIT,
    DEFENDERATP_DEVICE_VULNERABILITIES_DEFAULT_OFFSET,
    DEFENDER_LIST_DEVICE_VULNERABILITIES_ENDPOINT,
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


ListDeviceVulnerabilitiesOutput, ListDeviceVulnerabilitiesSummary = (
    get_action_output_types("list_device_vulnerabilities")
)


@app.action(
    read_only=True,
    description="Retrieve vulnerabilities affecting devices or software in organization",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/'
        'get-all-vulnerabilities-by-machines" target="_blank">Get Machines by Vulnerability API Documentation</a>).'
    ),
    summary_type=ListDeviceVulnerabilitiesSummary,
)
def list_device_vulnerabilities(
    params: ListDeviceVulnerabilitiesParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListDeviceVulnerabilitiesOutput]:
    """Return paginated machine vulnerability records filtered by the provided fields."""
    limit = _integer(
        params.limit
        if params.limit is not None
        else DEFENDERATP_DEVICE_VULNERABILITIES_DEFAULT_LIMIT,
        "limit",
        allow_zero=False,
    )
    offset = _integer(
        params.offset
        if params.offset is not None
        else DEFENDERATP_DEVICE_VULNERABILITIES_DEFAULT_OFFSET,
        "offset",
        allow_zero=True,
    )
    query_params = {"$top": limit, "$skip": offset}
    filters = []
    for field_name, api_name in (
        ("device_id", "machineId"),
        ("software_id", "softwareId"),
        ("cve_id", "cveId"),
        ("product_name", "productName"),
        ("product_version", "productVersion"),
        ("severity", "severity"),
        ("product_vendor", "productVendor"),
    ):
        value = getattr(params, field_name)
        if value:
            filters.append(f"{api_name} eq {odata_string_literal(value)}")
    if filters:
        query_params["$filter"] = " and ".join(filters)

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_LIST_DEVICE_VULNERABILITIES_ENDPOINT}",
        params=query_params,
    )
    vulnerabilities = response.get("value", [])
    outputs = [
        ListDeviceVulnerabilitiesOutput.model_validate(item | {"status": "success"})
        for item in vulnerabilities
    ]
    if not outputs:
        soar.set_message("No vulnerabilities found for specified device")
        return outputs

    soar.set_summary(
        ListDeviceVulnerabilitiesSummary(total_vulnerabilities=len(outputs))
    )
    soar.set_message(f"Total vulnerabilities: {len(outputs)}")
    return outputs
