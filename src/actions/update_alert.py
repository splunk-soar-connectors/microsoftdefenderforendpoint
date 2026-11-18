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
"""Update editable fields on a Defender for Endpoint alert."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, UpdateAlertParams
from ..consts import DEFENDERATP_ALERTS_ID_ENDPOINT, DEFENDERATP_NO_DATA_FOUND
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


UpdateAlertOutput, UpdateAlertSummary = get_action_output_types("update_alert")


def update_alert(
    params: UpdateAlertParams,
    soar: SOARClient,
    asset: Asset,
) -> list[UpdateAlertOutput]:
    """Patch the alert and return the updated record."""
    body = {}
    for name, value in (
        ("status", params.status),
        ("assignedTo", params.assigned_to),
        ("classification", params.classification),
        ("determination", params.determination),
        ("comment", params.comment),
    ):
        if value:
            body[name] = value

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "PATCH",
        f"{graph_url}{DEFENDERATP_ALERTS_ID_ENDPOINT.format(input=params.alert_id)}",
        json_body=body,
    )
    if not response:
        soar.set_message(DEFENDERATP_NO_DATA_FOUND)
        return []

    response_data = dict(response)
    output = UpdateAlertOutput.model_validate(response_data)
    soar.set_summary(UpdateAlertSummary(action_taken="Updated Alert"))
    soar.set_message("Action Taken: Updated Alert")
    return [output]
