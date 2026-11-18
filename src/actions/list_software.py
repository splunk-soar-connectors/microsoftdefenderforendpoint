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
"""Retrieve software inventory records from Defender for Endpoint."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, ListSoftwareParams, app
from ..consts import (
    DEFENDERATP_SOFTWARE_DEFAULT_LIMIT,
    DEFENDERATP_SOFTWARE_DEFAULT_OFFSET,
    DEFENDER_LIST_SOFTWARE_ENDPOINT,
    NON_NEGATIVE_INTEGER_MSG,
    POSITIVE_INTEGER_MSG,
    VALID_INTEGER_MSG,
)
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


def _to_nonnegative_integer(value, parameter_name: str, *, allow_zero: bool) -> int:
    try:
        number = float(value)
        if not number.is_integer():
            raise ValueError
        result = int(number)
    except (TypeError, ValueError) as error:
        raise ValueError(
            VALID_INTEGER_MSG.format(f"'{parameter_name}' action parameter")
        ) from error
    if result < 0:
        raise ValueError(
            NON_NEGATIVE_INTEGER_MSG.format(f"'{parameter_name}' action parameter")
        )
    if not allow_zero and result == 0:
        raise ValueError(
            POSITIVE_INTEGER_MSG.format(f"'{parameter_name}' action parameter")
        )
    return result


ListSoftwareOutput, ListSoftwareSummary = get_action_output_types("list_software")


@app.action(
    read_only=True,
    description="Retrieve the organization's software inventory",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-software" '
        'target="_blank">Get Software API Documentation</a>).'
    ),
    summary_type=ListSoftwareSummary,
)
def list_software(
    params: ListSoftwareParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListSoftwareOutput]:
    """Return software inventory matching the supplied filters."""
    limit = _to_nonnegative_integer(
        params.limit
        if params.limit is not None
        else DEFENDERATP_SOFTWARE_DEFAULT_LIMIT,
        "limit",
        allow_zero=False,
    )
    offset = _to_nonnegative_integer(
        params.offset
        if params.offset is not None
        else DEFENDERATP_SOFTWARE_DEFAULT_OFFSET,
        "offset",
        allow_zero=True,
    )

    _, _, graph_url = get_environment_urls(asset)
    query_params = {"$top": limit, "$skip": offset}
    for key, value in (
        ("id", params.id),
        ("name", params.name),
        ("vendor", params.vendor),
    ):
        if value:
            query_params[key] = value
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_LIST_SOFTWARE_ENDPOINT}",
        params=query_params,
    )
    software = response.get("value", [])
    outputs = [
        ListSoftwareOutput.model_validate(item | {"status": "success"})
        for item in software
    ]
    if not outputs:
        soar.set_message("No software found")
        return outputs

    soar.set_summary(ListSoftwareSummary(total_software=len(outputs)))
    soar.set_message(f"Total software: {len(outputs)}")
    return outputs
