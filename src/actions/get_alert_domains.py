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
"""List domains associated with a Defender alert."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, GetAlertDomainsParams, app
from ..consts import (
    DEFENDERATP_ALERTS_ID_ENDPOINT,
    DEFENDERATP_DOMAINS_DEFAULT_LIMIT,
    DEFENDERATP_DOMAINS_DEFAULT_OFFSET,
)
from ..helper import get_environment_urls, request_json
from ..output_models import get_action_output_types


GetAlertDomainsOutput, GetAlertDomainsSummary = get_action_output_types(
    "get_alert_domains"
)


@app.action(
    read_only=True,
    description="Retrieve domains for a specific Alert from its ID",
    action_type="investigate",
    render_as="table",
    summary_type=GetAlertDomainsSummary,
)
def get_alert_domains(
    params: GetAlertDomainsParams,
    soar: SOARClient,
    asset: Asset,
) -> list[GetAlertDomainsOutput]:
    """Return paginated domain evidence for an alert."""
    if not params.alert_id:
        raise ValueError("Missing required parameter: alert_id")

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_ALERTS_ID_ENDPOINT.format(input=params.alert_id)}/domains",
        params={
            "$top": params.limit
            if params.limit is not None
            else DEFENDERATP_DOMAINS_DEFAULT_LIMIT,
            "$skip": params.offset
            if params.offset is not None
            else DEFENDERATP_DOMAINS_DEFAULT_OFFSET,
        },
    )
    domains = response.get("value", [])
    outputs = [
        GetAlertDomainsOutput.model_validate(item | {"status": "success"})
        for item in domains
    ]
    soar.set_summary(
        GetAlertDomainsSummary(
            action_taken="Retrieved Domains for Alert", total_results=len(outputs)
        )
    )
    soar.set_message(
        f"Action taken: Retrieved Domains for Alert; Total results: {len(outputs)}"
    )
    return outputs
