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
"""Retrieve one Defender for Endpoint alert by ID."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetAlertParams
from ..consts import DEFENDERATP_ALERTS_ID_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetAlertOutput, GetAlertSummary = get_action_output_types("get_alert")


def get_alert(
    params: GetAlertParams,
    soar: SOARClient,
    asset: Asset,
) -> list[GetAlertOutput]:
    """Return the requested alert, preserving its API fields."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_ALERTS_ID_ENDPOINT.format(input=params.alert_id)}",
    )
    if not response:
        soar.set_message("No alert found")
        return []

    response_data = dict(response)
    soar.set_summary(GetAlertSummary(action_taken="Retrieved Alert"))
    soar.set_message("Action taken: Retrieved Alert")
    return [GetAlertOutput.model_validate(response_data)]
