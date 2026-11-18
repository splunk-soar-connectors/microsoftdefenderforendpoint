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
"""Return organization prevalence statistics for a domain."""

from soar_sdk.abstract import SOARClient

from ..app import Asset, DomainPrevalenceParams, app
from ..consts import (
    DEFENDERATP_DOMAIN_PREVALENCE_ENDPOINT,
    DEFENDERATP_MAX_LOOK_BACK_HOURS,
)
from ..helper import encode_domain, get_environment_urls, request_json
from ..output_models import get_action_output_types


DomainPrevalenceOutput, DomainPrevalenceSummary = get_action_output_types(
    "domain_prevalence"
)


@app.action(
    read_only=True,
    description="Return statistics for the specified domain",
    action_type="investigate",
    render_as="table",
    summary_type=DomainPrevalenceSummary,
)
def domain_prevalence(
    params: DomainPrevalenceParams,
    soar: SOARClient,
    asset: Asset,
) -> DomainPrevalenceOutput:
    """Fetch prevalence statistics over the requested look-back window."""
    raw_hours = params.look_back_hours if params.look_back_hours is not None else 720
    try:
        numeric_hours = float(raw_hours)
        look_back_hours = int(numeric_hours)
        if numeric_hours != look_back_hours or look_back_hours <= 0:
            raise ValueError
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Invalid look_back_hours parameter was given, must be greater than zero and lower or equal to 720."
        ) from error
    if look_back_hours > DEFENDERATP_MAX_LOOK_BACK_HOURS:
        raise ValueError(
            "Invalid look_back_hours parameter was given, must be greater than zero and lower or equal to 720."
        )

    _, _, graph_url = get_environment_urls(asset)
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_DOMAIN_PREVALENCE_ENDPOINT.format(domain=encode_domain(params.domain))}",
        params={"lookBackHours": look_back_hours},
    )
    if not response:
        raise RuntimeError("No data found")
    prevalence = response.get("organizationPrevalence", 0)
    soar.set_summary(DomainPrevalenceSummary(organization_prevalence=prevalence))
    soar.set_message(f"Organization prevalence: {prevalence}")
    return DomainPrevalenceOutput.model_validate(response)
