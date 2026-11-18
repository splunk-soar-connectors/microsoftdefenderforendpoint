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
"""Add or remove a device tag in Defender for Endpoint."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, UpdateDeviceTagParams, app
from ..consts import DEFENDERATP_MACHINES_TAGS_ENDPOINT, TAG_OPERATION_VALUE_LIST
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


UpdateDeviceTagOutput, UpdateDeviceTagSummary = get_action_output_types(
    "update_device_tag"
)


@app.action(
    description="Add or remove a tag from a given device (Maximum: 200 characters)",
    action_type="generic",
    read_only=False,
    render_as="table",
    summary_type=UpdateDeviceTagSummary,
)
def update_device_tag(
    params: UpdateDeviceTagParams,
    soar: SOARClient,
    asset: Asset,
) -> UpdateDeviceTagOutput:
    """Apply the selected tag operation and return the updated machine."""
    if params.operation not in TAG_OPERATION_VALUE_LIST:
        raise ValueError(
            f"Please provide valid input from {TAG_OPERATION_VALUE_LIST} in 'operation' action parameter"
        )
    if not params.tag:
        raise ValueError("Missing required parameter: tag")
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "POST",
        f"{graph_url}{DEFENDERATP_MACHINES_TAGS_ENDPOINT.format(device_id=params.device_id)}",
        json_body={"Action": params.operation, "Value": params.tag},
    )
    item = dict(response)
    soar.set_summary(UpdateDeviceTagSummary(tag=params.tag, operation=params.operation))
    return UpdateDeviceTagOutput.model_validate(item)
