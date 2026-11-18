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
import math
from datetime import UTC, datetime, timedelta
from collections.abc import Iterator
import httpx

from soar_sdk.auth import AuthorizationCodeFlow, ClientCredentialsFlow
from soar_sdk.auth.factories import create_oauth_callback_handler
from soar_sdk.abstract import SOARClient
from soar_sdk.app import App
from soar_sdk.params import Param, Params, OnPollParams
from soar_sdk.asset import BaseAsset, AssetField, FieldCategory
from soar_sdk.logging import getLogger
from soar_sdk.models.container import Container
from soar_sdk.models.artifact import Artifact
from soar_sdk.webhooks.models import WebhookRequest, WebhookResponse

from .consts import (
    DEFENDERATP_ALERTS_ENDPOINT,
    DEFENDER_ALERT_DEFAULT_LIMIT_FOR_SCHEDULE_POLLING,
    DEFENDER_ALERT_DEFAULT_TIME_RANGE,
)
from .helper import (
    get_environment_urls,
    get_oauth_client,
    get_oauth_config,
    request_json,
)

logger = getLogger()

MAX_ALERT_PAGE_SIZE = 10_000


def _parse_utc_datetime(value: str, name: str) -> datetime:
    """Parse an ISO-8601 timestamp and require a UTC timezone."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be an ISO-8601 UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{name} must be an ISO-8601 UTC timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must include a UTC timezone")
    return parsed.astimezone(UTC)


def _parse_epoch_milliseconds(value: int | float, name: str) -> datetime:
    """Convert an integral epoch-millisecond poll parameter to UTC."""
    if isinstance(value, bool):
        raise ValueError(f"{name} must be an integer epoch timestamp in milliseconds")
    try:
        number = float(value)
        milliseconds = int(number)
        if not math.isfinite(number) or number != milliseconds:
            raise ValueError
        return datetime.fromtimestamp(milliseconds / 1000, tz=UTC)
    except (OverflowError, OSError, TypeError, ValueError) as error:
        raise ValueError(
            f"{name} must be a valid integer epoch timestamp in milliseconds"
        ) from error


def _format_utc_datetime(value: datetime) -> str:
    return (
        value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    )


def _validate_alert_limit(value: int | float, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a non-negative integer")
    try:
        number = float(value)
        limit = int(number)
        if not math.isfinite(number) or number != limit or limit < 0:
            raise ValueError
    except (OverflowError, TypeError, ValueError) as error:
        raise ValueError(f"{name} must be a non-negative integer") from error
    return limit


class Asset(BaseAsset):
    tenant_id: str = AssetField(
        description="Tenant ID", category=FieldCategory.CONNECTIVITY
    )
    client_id: str = AssetField(
        description="Client ID", category=FieldCategory.CONNECTIVITY
    )
    client_secret: str = AssetField(
        description="Client Secret", sensitive=True, category=FieldCategory.CONNECTIVITY
    )
    non_interactive: bool | None = AssetField(
        description="Non Interactive Auth",
        default=False,
        category=FieldCategory.CONNECTIVITY,
    )
    max_alerts_per_poll: int | None = AssetField(
        description="Maximum Alerts for scheduled/interval polling for each cycle",
        default=1000,
        category=FieldCategory.INGEST,
    )
    start_time: str | None = AssetField(
        description="Start time for schedule/interval/manual poll (Use ISO 8601 UTC format: 2024-09-04T16:26:58Z)",
        category=FieldCategory.INGEST,
    )
    environment: str = AssetField(
        description="Azure environment to connect",
        default="Public",
        value_list=["Public", "GCC", "GCC High"],
        category=FieldCategory.CONNECTIVITY,
    )


app = App(
    name="Microsoft Defender for Endpoint",
    app_type="endpoint",
    logo="logo_microsoftdefenderforendpoint.svg",
    logo_dark="logo_microsoftdefenderforendpoint_dark.svg",
    product_vendor="Microsoft",
    product_name="Microsoft Defender for Endpoint",
    publisher="Splunk",
    appid="e85407b7-91f0-4019-8fa4-0d29bca741d5",
    fips_compliant=True,
    encrypt_cache_state=True,
    encrypt_ingest_state=True,
    asset_cls=Asset,
).enable_webhooks(default_requires_auth=False)


@app.on_poll()
def on_poll(
    params: OnPollParams, soar: SOARClient, asset: Asset
) -> Iterator[Container | Artifact]:
    """Ingest alerts updated in a bounded, resumable time window."""
    _, _, graph_url = get_environment_urls(asset)
    now = datetime.now(UTC)
    configured_start = (
        _parse_utc_datetime(asset.start_time, "start_time")
        if asset.start_time
        else None
    )
    if configured_start and configured_start > now:
        raise ValueError("start_time cannot be in the future")

    manual_poll = params.is_manual_poll()
    if manual_poll:
        raw_limit = params.container_count
        limit_name = "container_count"
    else:
        raw_limit = (
            asset.max_alerts_per_poll
            if asset.max_alerts_per_poll is not None
            else DEFENDER_ALERT_DEFAULT_LIMIT_FOR_SCHEDULE_POLLING
        )
        limit_name = "max_alerts_per_poll"
    max_alerts = _validate_alert_limit(raw_limit, limit_name)
    if max_alerts == 0:
        logger.info(f"Skipping alert polling because {limit_name} is zero.")
        return

    previous_checkpoint = asset.ingest_state.get("last_modified_time")
    if not previous_checkpoint:
        # SDK partitions share the legacy backend. Copy only its non-secret
        # checkpoint; never copy legacy encrypted OAuth tokens into SDK state.
        legacy_state = asset.ingest_state.backend.load_state() or {}
        previous_checkpoint = legacy_state.get("last_time")
        if previous_checkpoint:
            _parse_utc_datetime(previous_checkpoint, "legacy last_time")
            asset.ingest_state["last_modified_time"] = previous_checkpoint
    checkpoint = (
        _parse_utc_datetime(previous_checkpoint, "stored last_modified_time")
        if previous_checkpoint
        else None
    )

    if manual_poll:
        manual_continuation = asset.ingest_state.get("manual_alert_poll_window")
        if manual_continuation and (
            manual_continuation.get("requested_start_time") == params.start_time
            and manual_continuation.get("requested_end_time") == params.end_time
        ):
            continuation = manual_continuation
        else:
            if manual_continuation:
                asset.ingest_state.pop("manual_alert_poll_window", None)
            continuation = None
    else:
        continuation = asset.ingest_state.get("alert_poll_window")
    if continuation:
        try:
            start = _parse_utc_datetime(
                continuation["start_time"], "stored poll start_time"
            )
            end = _parse_utc_datetime(continuation["end_time"], "stored poll end_time")
            cursor = continuation.get("cursor")
            # Restart old offset windows safely; SDIs deduplicate replayed alerts.
            if cursor:
                _parse_utc_datetime(cursor["time"], "stored cursor time")
                if not isinstance(cursor["id"], str) or not cursor["id"]:
                    raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(
                "Stored alert polling continuation state is invalid"
            ) from error
    else:
        if params.start_time is not None:
            start = _parse_epoch_milliseconds(params.start_time, "start_time")
        elif checkpoint:
            start = checkpoint
        elif configured_start:
            start = configured_start
        else:
            start = now - timedelta(days=DEFENDER_ALERT_DEFAULT_TIME_RANGE)
        end = (
            _parse_epoch_milliseconds(params.end_time, "end_time")
            if params.end_time is not None
            else now
        )
        cursor = None

    if end < start:
        raise ValueError("end_time must be greater than or equal to start_time")

    start_time = _format_utc_datetime(start)
    end_time = _format_utc_datetime(end)
    logger.progress(
        f"Fetching up to {max_alerts} alerts updated from {start_time} through {end_time}."
    )

    fetched = 0
    exhausted_window = False
    while fetched < max_alerts:
        page_size = min(MAX_ALERT_PAGE_SIZE, max_alerts - fetched)
        alert_filter = (
            f"lastUpdateTime ge {start_time} and lastUpdateTime le {end_time}"
        )
        if cursor:
            cursor_id = cursor["id"].replace("'", "''")
            alert_filter += (
                f" and (lastUpdateTime gt {cursor['time']} or "
                f"(lastUpdateTime eq {cursor['time']} and id gt '{cursor_id}'))"
            )
        response = request_json(
            asset,
            "GET",
            f"{graph_url}{DEFENDERATP_ALERTS_ENDPOINT}",
            params={
                "$top": page_size,
                "$orderby": "lastUpdateTime asc,id asc",
                "$filter": alert_filter,
            },
        )
        alerts = response.get("value", [])
        if not isinstance(alerts, list):
            raise ValueError("Defender returned an invalid alert list during polling")
        if len(alerts) > page_size:
            raise ValueError(
                "Defender returned more alerts than the requested page size"
            )

        logger.info(f"Fetched {len(alerts)} alerts.")
        for alert in alerts:
            updated = alert.get("lastUpdateTime")
            _parse_utc_datetime(updated, "alert lastUpdateTime")
            if not isinstance(alert.get("id"), str) or not alert["id"]:
                raise ValueError("Defender returned an alert without an ID")
            next_cursor = {"time": updated, "id": alert["id"]}
            if cursor == next_cursor:
                raise ValueError("Defender returned a repeated polling cursor")
            severity = str(alert.get("severity", "low")).lower()
            if severity not in {"low", "medium", "high"}:
                severity = "low"
            identifier = alert.get("id")
            artifact = Artifact(
                label="alert",
                name=alert.get("title"),
                source_data_identifier=identifier,
                severity=severity,
                data=alert,
                cef=alert,
            )
            yield Container(
                name=alert.get("title")
                or str(identifier or "Microsoft Defender alert"),
                description="Alert ingested using MS Defender for Endpoint",
                source_data_identifier=identifier,
                severity=severity,
                artifacts=[artifact.model_dump(exclude_none=True)],
            )

            cursor = next_cursor

        fetched += len(alerts)
        if len(alerts) < page_size:
            exhausted_window = True
            break

    if manual_poll:
        if exhausted_window:
            asset.ingest_state.pop("manual_alert_poll_window", None)
        else:
            asset.ingest_state["manual_alert_poll_window"] = {
                "requested_start_time": params.start_time,
                "requested_end_time": params.end_time,
                "start_time": start_time,
                "end_time": end_time,
                "cursor": cursor,
            }
    else:
        if exhausted_window:
            asset.ingest_state["last_modified_time"] = end_time
            asset.ingest_state.pop("alert_poll_window", None)
        else:
            asset.ingest_state["alert_poll_window"] = {
                "start_time": start_time,
                "end_time": end_time,
                "cursor": cursor,
            }


@app.test_connectivity()
def test_connectivity(soar: SOARClient, asset: Asset) -> None:
    """Validate Azure credentials by querying one alert."""
    _, resource_url, graph_url = get_environment_urls(asset)
    config = get_oauth_config(asset, app.get_webhook_url("oauth_callback"))
    if asset.non_interactive:
        flow = ClientCredentialsFlow(
            asset.auth_state,
            client_id=asset.client_id,
            client_secret=asset.client_secret,
            token_endpoint=config.token_endpoint,
            extra_params={"resource": resource_url},
        )
        token = flow.get_token()
    else:
        flow = AuthorizationCodeFlow(
            asset.auth_state,
            soar.get_asset_id(),
            client_id=asset.client_id,
            client_secret=asset.client_secret,
            authorization_endpoint=config.authorization_endpoint,
            token_endpoint=config.token_endpoint,
            redirect_uri=config.redirect_uri,
            extra_auth_params={"resource": resource_url},
            extra_token_params={"resource": resource_url},
            poll_timeout=105,
            poll_interval=3,
        )
        authorization_url = flow.get_authorization_url()
        logger.progress(f"OAuth callback URL: {config.redirect_uri}")
        logger.progress(
            f"Please authorize Microsoft Defender for Endpoint: {authorization_url}"
        )
        token = flow.wait_for_authorization(
            on_progress=lambda iteration: logger.progress(
                f"Waiting for authorization ({iteration})"
            )
        )

    response = httpx.get(
        f"{graph_url}{DEFENDERATP_ALERTS_ENDPOINT}",
        params={"$top": 1},
        headers={
            "Authorization": f"Bearer {token.access_token}",
            "Accept": "application/json",
        },
        timeout=30.0,
    )
    response.raise_for_status()
    soar.set_message("Test connectivity passed")


@app.webhook("oauth_callback")
def oauth_callback(request: WebhookRequest[Asset]) -> WebhookResponse:
    """Receive the Microsoft authorization code through the SDK webhook."""
    return create_oauth_callback_handler(get_oauth_client)(request)


class QuarantineDeviceParams(Params):
    device_id: str = Param(
        description="ID of the device to quarantine",
        primary=True,
        cef_types=["defender atp device id"],
        column_name="Device ID",
    )
    type: str = Param(
        description="Type of quarantine (Default: Full)",
        default="Full",
        value_list=["Full", "Selective"],
        column_name="Quarantine Type",
    )
    comment: str = Param(description="Comment for quarantine", column_name="Comment")
    timeout: float | None = Param(
        description="Timeout in seconds (Default: 30)", default=30
    )


class GetStatusParams(Params):
    event_id: str = Param(
        description="ID of the event",
        primary=True,
        cef_types=["defender atp event id"],
        column_name="Event ID",
    )


class ScanDeviceParams(Params):
    device_id: str = Param(
        description="ID of the device to scan",
        primary=True,
        cef_types=["defender atp device id"],
        column_name="Device ID",
    )
    scan_type: str = Param(
        description="Type of scan",
        default="Quick",
        value_list=["Quick", "Full"],
        column_name="Scan Type",
    )
    comment: str = Param(description="Comment for scan", column_name="Comment")
    timeout: float | None = Param(
        description="Timeout in seconds (Default: 30)", default=30
    )


class QuarantineFileParams(Params):
    device_id: str = Param(
        description="ID of the device",
        primary=True,
        cef_types=["defender atp device id"],
        column_name="Device ID",
    )
    file_hash: str = Param(
        description="Identifier of the file",
        primary=True,
        cef_types=["sha1"],
        column_name="File Hash",
    )
    comment: str = Param(description="Comment for quarantine", column_name="Comment")
    timeout: float | None = Param(
        description="Timeout in seconds (Default: 30)", default=30
    )


class GetActiveUsersParams(Params):
    device_id: str = Param(
        description="ID of the device", cef_types=["defender atp device id"]
    )


class ListDevicesParams(Params):
    input_type: str = Param(
        description="Type of input (Default: All)",
        default="All",
        value_list=["All", "Domain", "File Hash"],
    )
    input: str | None = Param(
        description="Input filter of type Domain, File hash or All",
        primary=True,
        cef_types=["sha1", "sha256", "md5", "domain"],
    )
    query: str | None = Param(description="Additional OData V4 filters to apply")
    limit: float | None = Param(
        description="Maximum number of devices to return (Maximum: 10,000)", default=100
    )


class ListAlertsParams(Params):
    input_type: str | None = Param(
        description="Type of input (Default: All)",
        default="All",
        value_list=["All", "Domain", "File Hash", "IP"],
    )
    input: str | None = Param(
        description="Input filter of type Domain, File Hash, and IP",
        primary=True,
        cef_types=["domain", "sha1", "sha256", "md5", "ip"],
    )
    limit: float | None = Param(
        description="Maximum number of alerts to return (Maximum: 10,000)", default=100
    )


class ListSessionsParams(Params):
    device_id: str = Param(
        description="ID of the device",
        primary=True,
        cef_types=["defender atp device id"],
        column_name="Device ID",
    )


class ListSoftwareParams(Params):
    id: str | None = Param(
        description="ID of the software", cef_types=["defender atp software id"]
    )
    name: str | None = Param(description="Name of the software")
    vendor: str | None = Param(description="Vendor of the software")
    limit: float | None = Param(
        description="Maximum number of results to return", default=50
    )
    offset: float | None = Param(description="Number of results to offset", default=0)


class ListSoftwareVersionsParams(Params):
    id: str = Param(
        description="ID of the software", cef_types=["defender atp software id"]
    )


class ListSoftwareDevicesParams(Params):
    id: str = Param(
        description="ID of the software", cef_types=["defender atp software id"]
    )


class ListSoftwareVulnerabilitiesParams(Params):
    id: str = Param(
        description="ID of the software", cef_types=["defender atp software id"]
    )


class ListDeviceVulnerabilitiesParams(Params):
    device_id: str | None = Param(
        description="ID of the device", cef_types=["defender atp device id"]
    )
    software_id: str | None = Param(
        description="ID of the software", cef_types=["defender atp software id"]
    )
    cve_id: str | None = Param(description="CVE ID", cef_types=["cve id"])
    product_name: str | None = Param(description="Name of the product")
    product_version: str | None = Param(description="Version of the product")
    severity: str | None = Param(description="Severity of the vulnerability")
    product_vendor: str | None = Param(description="Vendor of the product")
    limit: float | None = Param(
        description="Maximum number of results to return", default=25
    )
    offset: float | None = Param(description="Number of results to skip", default=0)


class ListVulnerabilitiesParams(Params):
    id: str | None = Param(description="ID of the vulnerability", cef_types=["cve id"])
    name_equal: str | None = Param(description="Exact name of the vulnerability")
    name_contains: str | None = Param(description="Name contains this string")
    description_contains: str | None = Param(
        description="Description contains this string"
    )
    published_on: str | None = Param(
        description="Date when the vulnerability was published"
    )
    cvss: float | None = Param(description="CVSS score")
    severity: str | None = Param(description="Severity of the vulnerability")
    updated_on: str | None = Param(
        description="Date when the vulnerability was last updated"
    )
    limit: float | None = Param(
        description="Maximum number of results to return", default=25
    )
    offset: float | None = Param(description="Number of results to skip", default=0)


class GetAlertParams(Params):
    alert_id: str = Param(
        description="ID of the alert", primary=True, cef_types=["defender atp alert id"]
    )


class GetAlertUserParams(Params):
    alert_id: str = Param(
        description="ID of alert", primary=True, cef_types=["defender atp alert id"]
    )


class GetAlertFilesParams(Params):
    alert_id: str = Param(
        description="ID of the alert", primary=True, cef_types=["defender atp alert id"]
    )
    limit: float | None = Param(
        description="Maximum number of files to return", default=100
    )
    offset: float | None = Param(description="Offset for pagination", default=0)


class GetAlertIpsParams(Params):
    alert_id: str = Param(
        description="ID of the alert", primary=True, cef_types=["defender atp alert id"]
    )
    limit: float | None = Param(
        description="Maximum number of IP addresses to return", default=100
    )
    offset: float | None = Param(description="Offset for pagination", default=0)


class GetAlertDomainsParams(Params):
    alert_id: str = Param(
        description="ID of the alert", primary=True, cef_types=["defender atp alert id"]
    )
    limit: float | None = Param(
        description="Maximum number of domains to return", default=100
    )
    offset: float | None = Param(description="Offset for pagination", default=0)


class CreateAlertParams(Params):
    report_id: str = Param(description="Report ID of associated event")
    event_time: str = Param(
        description="UTC event time of associated event (Use this format: %Y-%m-%dT%H:%M:%SZ in UTC timezone)"
    )
    device_id: str = Param(
        description="Device ID of associated event",
        cef_types=["defender atp device id"],
    )
    severity: str = Param(
        description="Severity level of alert",
        value_list=["Informational", "Low", "Medium", "High"],
    )
    title: str = Param(description="Alert title")
    description: str = Param(description="Alert description")
    recommended_action: str = Param(description="Recommended action for alert")
    category: str = Param(
        description="Category of alert",
        value_list=[
            "General",
            "CommandAndControl",
            "Collection",
            "CredentialAccess",
            "DefenseEvasion",
            "Discovery",
            "Exfiltration",
            "Exploit",
            "Execution",
            "InitialAccess",
            "LateralMovement",
            "Malware",
            "Persistence",
            "PrivilegeEscalation",
            "Ransomware",
            "SuspiciousActivity",
        ],
    )


class UpdateAlertParams(Params):
    alert_id: str = Param(
        description="ID of the alert", primary=True, cef_types=["defender atp alert id"]
    )
    status: str | None = Param(
        description="Specifies the current status of the alert",
        value_list=["New", "InProgress", "Resolved"],
    )
    assigned_to: str | None = Param(
        description="Owner of the alert", primary=True, cef_types=["email"]
    )
    classification: str | None = Param(
        description="Specifies the specification of the alert",
        value_list=["Unknown", "FalsePositive", "TruePositive"],
    )
    determination: str | None = Param(
        description="Specifies the determination of the alert",
        value_list=[
            "NotAvailable",
            "Malware",
            "SecurityTesting",
            "UnwantedSoftware",
            "Other",
        ],
    )
    comment: str | None = Param(description="Comment to be added to the alert")


class DomainPrevalenceParams(Params):
    domain: str = Param(
        description="Domain to get the statistics", primary=True, cef_types=["domain"]
    )
    look_back_hours: float | None = Param(
        description="Define the hours you search back to get the statistics (Default: 720 hours (30 days))",
        default="720",
    )


class IpPrevalenceParams(Params):
    ip: str = Param(
        description="IP to get the statistics", primary=True, cef_types=["ip", "ipv6"]
    )
    look_back_hours: float | None = Param(
        description="Define the hours you search back to get the statistics (Default: 720 hours (30 days))",
        default="720",
    )


class FilePrevalenceParams(Params):
    file_hash: str = Param(
        description="File hash to get the statistics (SHA1 or SHA256)",
        primary=True,
        cef_types=["sha1", "sha256"],
    )
    look_back_hours: float | None = Param(
        description="Define the hours you search back to get the statistics (Default: 720 hours (30 days))",
        default="720",
    )


class GetFileInfoParams(Params):
    file_hash: str = Param(
        description="Identifier of the file", primary=True, cef_types=["sha1", "sha256"]
    )


class GetFileDevicesParams(Params):
    file_hash: str = Param(
        description="Identifier of the file", primary=True, cef_types=["sha1"]
    )


class GetUserDevicesParams(Params):
    user_id: str = Param(
        description="ID of the user", primary=True, cef_types=["user name"]
    )


class GetInstalledSoftwareParams(Params):
    device_id: str = Param(
        description="ID of the device",
        primary=True,
        cef_types=["defender atp device id"],
        column_name="Device ID",
    )


class RestrictAppExecutionParams(Params):
    device_id: str = Param(
        description="ID of the device",
        primary=True,
        cef_types=["defender atp device id"],
        column_name="Device ID",
    )
    comment: str = Param(description="Comment", column_name="Comment")
    timeout: float | None = Param(
        description="Timeout in seconds (Default: 30)", default=30
    )


class ListIndicatorsParams(Params):
    filter: str | None = Param(description="Additional OData V4 filters to apply")
    limit: float | None = Param(
        description="Maximum number of indicators to return (Maximum: 10,000)",
        default=100,
    )


class CollectInvestigationPackageParams(Params):
    device_id: str = Param(
        description="ID of the device", cef_types=["defender atp device id"]
    )
    comment: str = Param(description="Comment to include in the investigation package")


class GetInvestigationUriParams(Params):
    action_id: str = Param(
        description="ID of the investigation action",
        cef_types=["defender atp action id"],
    )


class GetDeviceDetailsParams(Params):
    device_ids: str = Param(description="Comma-separated list of device IDs")


class GetAffectedDevicesParams(Params):
    cve_id: str = Param(description="CVE ID of the vulnerability", cef_types=["cve id"])


class GetIndicatorParams(Params):
    indicator_id: str = Param(
        description="The ID of the indicator to retrieve",
        primary=True,
        cef_types=["defender atp indicator id"],
    )


class SubmitIndicatorParams(Params):
    title: str = Param(description="Indicator alert title")
    description: str = Param(description="Description of the indicator")
    indicator_type: str = Param(description="Type of the indicator")
    indicator_value: str = Param(
        description="Identity of the Indicator entity",
        primary=True,
        cef_types=[
            "defender atp indicator value",
            "sha1",
            "sha256",
            "md5",
            "ip",
            "ipv6",
            "url",
            "domain",
        ],
    )
    action: str = Param(
        description="The action that will be taken if the indicator will be discovered in the organization"
    )
    application: str | None = Param(
        description="The application associated with the indicator"
    )
    expiration_time: str | None = Param(
        description="The expiration time of the indicator (Use this format: %Y-%m-%dT%H:%M:%SZ in UTC timezone)"
    )
    severity: str | None = Param(
        description="The severity of the indicator",
        value_list=["Informational", "Low", "Medium", "High"],
    )
    recommended_actions: str | None = Param(
        description="TI indicator alert recommended actions"
    )
    rbac_group_names: str | None = Param(
        description="RBAC group names the indicator would be applied to (JSON formatted list)"
    )
    generate_alert: bool | None = Param(
        description="Whether or not this indicator should generate an alert",
        default=False,
    )


class UpdateIndicatorParams(Params):
    indicator_value: str = Param(
        description="The identity value of the indicator to update",
        primary=True,
        cef_types=[
            "defender atp indicator value",
            "sha1",
            "sha256",
            "md5",
            "ip",
            "ipv6",
            "url",
            "domain",
        ],
    )
    indicator_type: str = Param(
        description="The type of indicator",
        value_list=[
            "FileSha1",
            "FileSha256",
            "FileMd5",
            "CertificateThumbprint",
            "IpAddress",
            "DomainName",
            "Url",
        ],
    )
    action: str = Param(
        description="Action taken if the indicator is discovered",
        value_list=[
            "Warn",
            "Block",
            "Audit",
            "Alert",
            "AlertAndBlock",
            "BlockAndRemediate",
            "Allowed",
        ],
    )
    severity: str | None = Param(
        description="The severity of the malicious behavior identified by the indicator",
        value_list=["Informational", "Low", "Medium", "High"],
    )
    indicator_description: str = Param(description="Description of the indicator")
    indicator_title: str = Param(description="Indicator alert title")
    expiration_time: str | None = Param(
        description="The expiration time of the indicator (Use this format: %Y-%m-%dT%H:%M:%SZ in UTC timezone)"
    )
    indicator_application: str | None = Param(
        description="The application associated with the indicator"
    )
    recommended_actions: str | None = Param(
        description="TI indicator alert recommended actions"
    )
    rbac_group_names: str | None = Param(
        description="JSON formatted list of RBAC group names"
    )


class UpdateIndicatorBatchParams(Params):
    indicator_batch: str = Param(
        description="A JSON object with a list of indicators to update or create. Each indicator should include properties like indicatorValue, indicatorType, action, title, etc.",
        primary=True,
    )


class GetFileAlertsParams(Params):
    file_hash: str = Param(
        description="The file hash (e.g., SHA1) used to retrieve related alerts",
        primary=True,
        cef_types=["sha1", "sha256", "file_hash"],
    )


class GetDeviceAlertsParams(Params):
    device_id: str = Param(
        description="The device ID of the device to retrieve related alerts",
        primary=True,
        cef_types=["defender atp device id"],
    )


class GetUserAlertsParams(Params):
    user: str = Param(description="The user to retrieve alerts for", primary=True)


class GetDomainAlertsParams(Params):
    domain: str = Param(
        description="The domain address to retrieve alerts for",
        primary=True,
        cef_types=["domain"],
    )


class DeleteIndicatorParams(Params):
    indicator_id: str = Param(
        description="Indicator ID to delete",
        primary=True,
        cef_types=["defender atp indicator id"],
        column_name="Indicator ID",
    )


class RunQueryParams(Params):
    query: str = Param(description="Query to fetch results")


class GetDomainDevicesParams(Params):
    domain: str = Param(
        description="Domain to get the devices", primary=True, cef_types=["domain"]
    )


class UpdateDeviceTagParams(Params):
    device_id: str = Param(
        description="ID of the device",
        primary=True,
        cef_types=["defender atp device id"],
    )
    operation: str = Param(
        description="Determines whether the provided tag is added or removed",
        default="Add",
        value_list=["Add", "Remove"],
    )
    tag: str = Param(description="Value of the tag to add or remove from the machine")


class GetDiscoveredVulnerabilitiesParams(Params):
    device_id: str = Param(
        description="ID of the device",
        primary=True,
        cef_types=["defender atp device id"],
        column_name="Device ID",
    )


class RemoveAppRestrictionParams(Params):
    device_id: str = Param(
        description="ID of the device",
        primary=True,
        cef_types=["defender atp device id"],
        column_name="Device ID",
    )
    comment: str = Param(description="Comment", column_name="Comment")
    timeout: float | None = Param(
        description="Timeout in seconds (Default: 30)", default=30
    )


class GetFileParams(Params):
    event_id: str | None = Param(
        description="ID of the event", primary=True, cef_types=["defender atp event id"]
    )
    device_id: str | None = Param(
        description="ID of the device",
        primary=True,
        cef_types=["defender atp device id"],
        column_name="Device ID",
    )
    file_path: str | None = Param(
        description="Path of the file to download from device",
        primary=True,
        cef_types=["file path"],
        column_name="File Path",
    )
    comment: str | None = Param(description="Comment")
    timeout: float | None = Param(description="Timeout in seconds (Default: 300)")


class PutFileParams(Params):
    device_id: str = Param(
        description="ID of the device",
        primary=True,
        cef_types=["defender atp device id"],
        column_name="Device ID",
    )
    file_name: str = Param(
        description="Name of the file",
        primary=True,
        cef_types=["file name"],
        column_name="File Name",
    )
    comment: str = Param(description="Comment")
    timeout: float | None = Param(
        description="Timeout in seconds (Default: 300)", default=300
    )


class CancelLiveResponseParams(Params):
    action_id: str = Param(
        description="ID of the live response action to cancel",
        cef_types=["defender atp action id"],
    )
    comment: str = Param(description="Comment explaining the reason for cancellation")


class RunScriptParams(Params):
    event_id: str | None = Param(
        description="ID of the event", primary=True, cef_types=["defender atp event id"]
    )
    device_id: str | None = Param(
        description="ID of the device",
        primary=True,
        cef_types=["defender atp device id"],
    )
    script_name: str | None = Param(
        description="Name of the script file to execute on the device",
        primary=True,
        cef_types=["file name"],
    )
    script_args: str | None = Param(description="Arguments of the script file")
    comment: str | None = Param(description="Comment")
    timeout: float | None = Param(description="Timeout in seconds (Default: 300)")


class GetMissingKbsParams(Params):
    device_id: str = Param(
        description="ID of the device",
        primary=True,
        cef_types=["defender atp device id"],
    )


from .actions.quarantine_device import (
    QuarantineDeviceOutput,
    QuarantineDeviceSummary,
    quarantine_device,
)
from .actions.get_status import get_status  # noqa: F401
from .actions.scan_device import scan_device  # noqa: F401
from .actions.quarantine_file import quarantine_file  # noqa: F401
from .actions.unquarantine_device import unquarantine_device  # noqa: F401
from .actions.get_active_users import get_active_users  # noqa: F401
from .actions.list_devices import list_devices  # noqa: F401
from .actions.list_alerts import ListAlertsOutput, ListAlertsSummary, list_alerts
from .actions.list_sessions import list_sessions  # noqa: F401
from .actions.list_software import list_software  # noqa: F401
from .actions.list_software_versions import list_software_versions  # noqa: F401
from .actions.list_software_devices import list_software_devices  # noqa: F401
from .actions.list_software_vulnerabilities import list_software_vulnerabilities  # noqa: F401
from .actions.list_device_vulnerabilities import list_device_vulnerabilities  # noqa: F401
from .actions.list_vulnerabilities import list_vulnerabilities  # noqa: F401
from .actions.get_alert import GetAlertOutput, GetAlertSummary, get_alert
from .actions.get_alert_user import get_alert_user  # noqa: F401
from .actions.get_alert_files import get_alert_files  # noqa: F401
from .actions.get_alert_ips import get_alert_ips  # noqa: F401
from .actions.get_alert_domains import get_alert_domains  # noqa: F401
from .actions.create_alert import create_alert  # noqa: F401
from .actions.update_alert import UpdateAlertOutput, UpdateAlertSummary, update_alert
from .actions.domain_prevalence import domain_prevalence  # noqa: F401
from .actions.ip_prevalence import ip_prevalence  # noqa: F401
from .actions.file_prevalence import file_prevalence  # noqa: F401
from .actions.get_file_info import get_file_info  # noqa: F401
from .actions.get_file_related_devices import get_file_related_devices  # noqa: F401
from .actions.get_user_related_devices import get_user_related_devices  # noqa: F401
from .actions.get_domain_related_devices import get_domain_related_devices  # noqa: F401
from .actions.get_installed_software import get_installed_software  # noqa: F401
from .actions.restrict_app_execution import restrict_app_execution  # noqa: F401
from .actions.list_indicators import list_indicators  # noqa: F401
from .actions.collect_investigation_package import collect_investigation_package  # noqa: F401
from .actions.get_investigation_uri import get_investigation_uri  # noqa: F401
from .actions.get_device_details import get_device_details  # noqa: F401
from .actions.get_affected_devices import get_affected_devices  # noqa: F401
from .actions.get_indicator import get_indicator  # noqa: F401
from .actions.submit_indicator import submit_indicator  # noqa: F401
from .actions.update_indicator import update_indicator  # noqa: F401
from .actions.update_indicator_batch import update_indicator_batch  # noqa: F401
from .actions.delete_indicator import delete_indicator  # noqa: F401
from .actions.run_query import run_query  # noqa: F401
from .actions.get_discovered_vulnerabilities import get_discovered_vulnerabilities  # noqa: F401
from .actions.get_exposure_score import get_exposure_score  # noqa: F401
from .actions.get_secure_score import get_secure_score  # noqa: F401
from .actions.get_file_alerts import get_file_alerts  # noqa: F401
from .actions.get_device_alerts import get_device_alerts  # noqa: F401
from .actions.get_user_alerts import get_user_alerts  # noqa: F401
from .actions.get_domain_alerts import get_domain_alerts  # noqa: F401
from .actions.update_device_tag import update_device_tag  # noqa: F401
from .actions.remove_app_restriction import remove_app_restriction  # noqa: F401
from .actions.cancel_live_response import cancel_live_response  # noqa: F401
from .actions.get_file_live_response import get_file_live_response  # noqa: F401
from .actions.put_file_live_response import put_file_live_response  # noqa: F401
from .actions.run_script_live_response import (
    RunScriptOutput as RunScriptSDKOutput,
    RunScriptSummary,
    run_script_live_response,
)
from .actions.get_missing_kbs import get_missing_kbs  # noqa: F401
from .actions.make_request import make_request  # noqa: F401
from .views import render_run_script
from .views import render_list_alerts
from .views import render_get_alert
from .views import render_update_alert

app.register_action(
    quarantine_device,
    name="quarantine device",
    identifier="quarantine_device",
    description="Quarantine the device",
    action_type="contain",
    read_only=False,
    render_as="table",
    params_class=QuarantineDeviceParams,
    output_class=QuarantineDeviceOutput,
    summary_type=QuarantineDeviceSummary,
)

app.register_action(
    list_alerts,
    identifier="list_alerts",
    description="List all alerts of a given type",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/windows/security/threat-protection/'
        'microsoft-defender-atp/get-alerts" target="_blank">List Alerts API Documentation</a>), the user can '
        "get alerts last updated in the past 30 days; the maximum page size is 10,000; rate limitations for "
        "this action are 100 calls per minute and 1500 calls per hour. If the user does not specify the limit "
        "value, it will fetch 100 alerts by default."
    ),
    action_type="investigate",
    read_only=True,
    params_class=ListAlertsParams,
    output_class=ListAlertsOutput,
    summary_type=ListAlertsSummary,
    view_handler=render_list_alerts,
    view_template="list_alerts.html",
)

app.register_action(
    get_alert,
    identifier="get_alert",
    description="Retrieve specific Alert by its ID",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'get-alert-info-by-id" target="_blank">Get Alert Information by ID API Documentation</a>), user can '
        "get alerts last updated according to your configured retention period.; rate limitations for this action "
        "are 100 calls per minute and 1500 calls per hour."
    ),
    action_type="investigate",
    read_only=True,
    params_class=GetAlertParams,
    output_class=GetAlertOutput,
    summary_type=GetAlertSummary,
    view_handler=render_get_alert,
    view_template="get_alert.html",
)

app.register_action(
    update_alert,
    identifier="update_alert",
    description="Update properties of existing Alert",
    verbose=(
        'Based on the link (<a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/'
        'update-alert" target="_blank">Get Alert Information by ID API Documentation</a>), user can update '
        "alerts that available in the API. See List Alerts for more information. Also, previously supported alert "
        "determination values ('Apt' and 'SecurityPersonnel') have been deprecated and no longer available via the "
        "API; rate limitations for this action are 100 calls per minute and 1500 calls per hour."
    ),
    action_type="investigate",
    read_only=False,
    params_class=UpdateAlertParams,
    output_class=UpdateAlertOutput,
    summary_type=UpdateAlertSummary,
    view_handler=render_update_alert,
    view_template="update_alert.html",
)

app.register_action(
    run_script_live_response,
    name="run script",
    identifier="run_script_live_response",
    description="Run a script from the library on a device using live response",
    verbose=(
        'Based on the <a href="https://docs.microsoft.com/en-us/microsoft-365/security/defender-endpoint/run-live-response?view=o365-worldwide" '
        'target="_blank">Run live response commands API Documentation</a>. The script_args parameter is passed to the script. '
        "The action checks status every five seconds and returns the latest status if it is still running. The maximum timeout is 10 minutes."
    ),
    action_type="generic",
    read_only=False,
    params_class=RunScriptParams,
    output_class=RunScriptSDKOutput,
    summary_type=RunScriptSummary,
    view_handler=render_run_script,
    view_template="run_script.html",
)

if __name__ == "__main__":
    app.cli()
