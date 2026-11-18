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
"""List users who have logged on to a Defender for Endpoint device."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetActiveUsersParams, app
from ..consts import DEFENDER_GET_ACTIVE_DEVICE_USERS
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetActiveUsersOutput, GetActiveUsersSummary = get_action_output_types(
    "get_active_users"
)


@app.action(
    read_only=True,
    description="Get active users on a device",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://learn.microsoft.com/en-us/defender-endpoint/api/get-machine-log-on-users" '
        'target="_blank">Get Active Users API Documentation</a>).'
    ),
    summary_type=GetActiveUsersSummary,
)
def get_active_users(
    params: GetActiveUsersParams,
    soar: SOARClient,
    asset: Asset,
) -> list[GetActiveUsersOutput]:
    """Return active logon records for the requested device."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDER_GET_ACTIVE_DEVICE_USERS.format(device_id=params.device_id)}",
    )
    users = response.get("value", [])
    if not isinstance(users, list):
        raise RuntimeError("The response did not contain a valid user list")

    outputs = []
    for user in users:
        user_data = dict(user)
        outputs.append(
            GetActiveUsersOutput.model_validate(user_data | {"status": "success"})
        )

    soar.set_summary(
        GetActiveUsersSummary(
            action_taken="Retrieved Active Users", total_results=len(outputs)
        )
    )
    return outputs
