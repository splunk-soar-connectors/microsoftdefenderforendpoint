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
"""List Defender for Endpoint alerts filtered by type and value."""

import ipaddress
import re

from soar_sdk.abstract import SOARClient

from ..app import Asset, ListAlertsParams
from ..consts import (
    DEFENDERATP_ALERTS_ENDPOINT,
    DEFENDERATP_DOMAIN_ALERTS_ENDPOINT,
    DEFENDERATP_FILE_ALERTS_ENDPOINT,
    DEFENDERATP_INPUT_REQUIRED_MSG,
    DEFENDERATP_IP_ALERTS_ENDPOINT,
    DEFENDERATP_PARAM_VALIDATION_FAILED_MSG,
    DEFENDERATP_ALERT_DEFAULT_LIMIT,
    DEFENDERATP_ALL_CONST,
    DEFENDERATP_DOMAIN_CONST,
    DEFENDERATP_FILE_HASH_CONST,
    DEFENDERATP_IP_CONST,
    INPUT_TYPE_VALUE_LIST_ALERTS,
    LIMIT_KEY,
    NON_NEGATIVE_INTEGER_MSG,
    VALID_INTEGER_MSG,
)
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


ListAlertsOutput, ListAlertsSummary = get_action_output_types("list_alerts")


def _is_valid_domain(value: str) -> bool:
    if len(value) > 253:
        return False
    return all(
        0 < len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in value.rstrip(".").split(".")
    )


def _is_valid_hash(value: str) -> bool:
    return (
        re.fullmatch(r"(?i)(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value)
        is not None
    )


def list_alerts(
    params: ListAlertsParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListAlertsOutput]:
    """Fetch alerts for the selected IP, domain, hash, or all alerts."""
    input_type = params.input_type or DEFENDERATP_ALL_CONST
    if input_type not in INPUT_TYPE_VALUE_LIST_ALERTS:
        raise ValueError(
            f"Please provide valid input from {INPUT_TYPE_VALUE_LIST_ALERTS} in 'input_type' action parameter"
        )

    raw_limit = (
        params.limit if params.limit is not None else DEFENDERATP_ALERT_DEFAULT_LIMIT
    )
    try:
        limit_as_float = float(raw_limit)
        if not limit_as_float.is_integer():
            raise ValueError
        limit = int(limit_as_float)
    except (TypeError, ValueError) as error:
        raise ValueError(VALID_INTEGER_MSG.format(LIMIT_KEY)) from error
    if limit < 0:
        raise ValueError(NON_NEGATIVE_INTEGER_MSG.format(LIMIT_KEY))

    endpoint = DEFENDERATP_ALERTS_ENDPOINT
    value = params.input or ""
    if input_type != DEFENDERATP_ALL_CONST:
        if not value:
            raise ValueError(DEFENDERATP_INPUT_REQUIRED_MSG)
        if input_type == DEFENDERATP_IP_CONST:
            try:
                ipaddress.ip_address(value)
            except ValueError as error:
                raise ValueError(
                    DEFENDERATP_PARAM_VALIDATION_FAILED_MSG.format(DEFENDERATP_IP_CONST)
                ) from error
            endpoint = DEFENDERATP_IP_ALERTS_ENDPOINT.format(input=value)
        elif input_type == DEFENDERATP_DOMAIN_CONST:
            if not _is_valid_domain(value):
                raise ValueError(
                    DEFENDERATP_PARAM_VALIDATION_FAILED_MSG.format(
                        DEFENDERATP_DOMAIN_CONST
                    )
                )
            endpoint = DEFENDERATP_DOMAIN_ALERTS_ENDPOINT.format(input=value)
        elif input_type == DEFENDERATP_FILE_HASH_CONST:
            if not _is_valid_hash(value):
                raise ValueError(
                    DEFENDERATP_PARAM_VALIDATION_FAILED_MSG.format(
                        DEFENDERATP_FILE_HASH_CONST
                    )
                )
            endpoint = DEFENDERATP_FILE_ALERTS_ENDPOINT.format(input=value)

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(asset, "GET", f"{graph_url}{endpoint}?$top={limit}")
    if not response:
        raise RuntimeError("No data found")
    alerts = response.get("value", [])
    if not alerts:
        raise RuntimeError("No alerts found")

    outputs = []
    for alert in alerts:
        alert_data = dict(alert)
        outputs.append(ListAlertsOutput.model_validate(alert_data))

    soar.set_summary(ListAlertsSummary(total_alerts=len(outputs)))
    soar.set_message(f"Total alerts: {len(outputs)}")
    return outputs
