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
"""List Defender for Endpoint devices using optional filters."""

import re

from soar_sdk.abstract import SOARClient

from ..app import Asset, ListDevicesParams, app
from ..consts import (
    DEFENDERATP_DOMAIN_MACHINES_ENDPOINT,
    DEFENDERATP_FILE_MACHINES_ENDPOINT,
    DEFENDERATP_INPUT_REQUIRED_MSG,
    DEFENDERATP_MACHINES_ENDPOINT,
    DEFENDERATP_PARAM_VALIDATION_FAILED_MSG,
    INPUT_TYPE_VALUE_LIST_DEVICES,
    LIMIT_KEY,
    NON_NEGATIVE_INTEGER_MSG,
    VALID_INTEGER_MSG,
)
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


def _is_valid_domain(value: str) -> bool:
    if len(value) > 253:
        return False
    labels = value.rstrip(".").split(".")
    return all(
        0 < len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


ListDevicesOutput, ListDevicesSummary = get_action_output_types("list_devices")


@app.action(
    read_only=True,
    description="List of recently seen devices",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/'
        'microsoft-defender-atp/get-machines" target="_blank">List Machines API Documentation</a>), '
        "the user can get devices last seen in the past 30 days; the maximum page size is 10,000; rate "
        "limitations for this action are 100 calls per minute and 1500 calls per hour. If the user does not "
        "specify the limit value, it will fetch 100 devices by default."
    ),
    summary_type=ListDevicesSummary,
)
def list_devices(
    params: ListDevicesParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListDevicesOutput]:
    """Fetch device records from the selected Defender endpoint."""
    if params.input_type not in INPUT_TYPE_VALUE_LIST_DEVICES:
        raise ValueError(
            f"Please provide valid input from {INPUT_TYPE_VALUE_LIST_DEVICES} in 'input_type' action parameter"
        )

    raw_limit = params.limit if params.limit is not None else 100
    try:
        limit_as_float = float(raw_limit)
        if not limit_as_float.is_integer():
            raise ValueError
        limit = int(limit_as_float)
    except (TypeError, ValueError) as error:
        raise ValueError(VALID_INTEGER_MSG.format(LIMIT_KEY)) from error
    if limit < 0:
        raise ValueError(NON_NEGATIVE_INTEGER_MSG.format(LIMIT_KEY))

    endpoint = DEFENDERATP_MACHINES_ENDPOINT
    if params.input_type != "All":
        if not params.input:
            raise ValueError(DEFENDERATP_INPUT_REQUIRED_MSG)
        if params.input_type == "Domain":
            if not _is_valid_domain(params.input):
                raise ValueError(
                    DEFENDERATP_PARAM_VALIDATION_FAILED_MSG.format("Domain")
                )
            endpoint = DEFENDERATP_DOMAIN_MACHINES_ENDPOINT.format(input=params.input)
        elif params.input_type == "File Hash":
            if not re.fullmatch(
                r"(?i)(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", params.input
            ):
                raise ValueError(
                    DEFENDERATP_PARAM_VALIDATION_FAILED_MSG.format("File Hash")
                )
            endpoint = DEFENDERATP_FILE_MACHINES_ENDPOINT.format(input=params.input)

    _, _, graph_url = get_environment_urls(asset)
    query_suffix = params.query or ""
    url = f"{graph_url}{endpoint}?$top={limit}&{query_suffix}"
    response = request_json(asset, "GET", url)
    if not response:
        raise RuntimeError("No data found")

    machines = response.get("value", [])
    if not machines:
        raise RuntimeError("No device found")

    outputs = []
    for machine in machines:
        machine_data = dict(machine)
        outputs.append(
            ListDevicesOutput.model_validate(machine_data | {"status": "success"})
        )

    soar.set_summary(ListDevicesSummary(total_devices=len(outputs)))
    soar.set_message(f"Total devices: {len(outputs)}")
    return outputs
