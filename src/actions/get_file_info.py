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
"""Retrieve information for a file identified by SHA1 or SHA256."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetFileInfoParams, app
from ..consts import DEFENDERATP_FILE_INFO_ENDPOINT
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetFileInfoOutput, GetFileInfoSummary = get_action_output_types("get_file_info")


@app.action(
    read_only=True,
    description="Retrieve a File information by identifier SHA1, or SHA256",
    action_type="investigate",
    render_as="table",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'get-file-information?view=o365-worldwide" target="_blank">Get File Information API Documentation</a>), '
        "rate limitations for this action are 100 calls per minute and 1500 calls per hour. The valid file identifiers "
        "are SHA1, SHA256."
    ),
    summary_type=GetFileInfoSummary,
)
def get_file_info(
    params: GetFileInfoParams,
    soar: SOARClient,
    asset: Asset,
) -> GetFileInfoOutput:
    """Fetch the file record and report its global prevalence."""
    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_FILE_INFO_ENDPOINT.format(file_hash=params.file_hash)}",
    )
    if not response:
        raise RuntimeError("No data found")
    soar.set_summary(
        GetFileInfoSummary(global_prevalence=response.get("globalPrevalence", 0))
    )
    soar.set_message("Successfully retrieved file information")
    return GetFileInfoOutput.model_validate(
        {**response, "status": "success", "file_hash": params.file_hash}
    )
