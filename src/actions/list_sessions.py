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
"""List users who have signed in to a Defender for Endpoint device."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, ListSessionsParams, app
from ..consts import DEFENDERATP_SESSIONS_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


ListSessionsOutput, ListSessionsSummary = get_action_output_types("list_sessions")


@app.action(
    read_only=True,
    description="List all logged in users on a machine",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/'
        'microsoft-defender-atp/get-machine-log-on-users" target="_blank">List Sessions API Documentation</a>), '
        "the user can query on machines last seen in the past 30 days; rate limitations for this action are "
        "100 calls per minute and 1500 calls per hour."
    ),
    summary_type=ListSessionsSummary,
)
def list_sessions(
    params: ListSessionsParams,
    soar: SOARClient,
    asset: Asset,
) -> list[ListSessionsOutput]:
    """Return the logon records for the requested device."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_SESSIONS_ENDPOINT.format(device_id=params.device_id)}",
    )
    sessions = response.get("value", [])
    if not sessions:
        raise RuntimeError("No sessions found for the given device")

    outputs = []
    for session in sessions:
        session_data = dict(session)
        outputs.append(
            ListSessionsOutput.model_validate(session_data | {"status": "success"})
        )

    soar.set_summary(ListSessionsSummary(total_sessions=len(outputs)))
    soar.set_message(f"Total sessions: {len(outputs)}")
    return outputs
