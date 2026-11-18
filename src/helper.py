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
"""Authentication and HTTP helpers for Microsoft Defender for Endpoint."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import quote, unquote, urlsplit

import httpx

from soar_sdk.action_results import ActionOutput, ActionResult
from soar_sdk.auth import ClientCredentialsFlow
from soar_sdk.auth.client import (
    AuthorizationRequiredError,
    SOARAssetOAuthClient,
    TokenExpiredError,
)
from soar_sdk.auth.models import OAuthConfig, OAuthState, OAuthToken

from .consts import (
    DEFENDERATP_LOGIN_BASE_URL,
    DEFENDERATP_LOGIN_GCC_HIGH_BASE_URL,
    DEFENDERATP_MSGRAPH_API_BASE_URL,
    DEFENDERATP_MSGRAPH_API_GCC_BASE_URL,
    DEFENDERATP_MSGRAPH_API_GCC_HIGH_BASE_URL,
    DEFENDERATP_RESOURCE_GCC_HIGH_URL,
    DEFENDERATP_RESOURCE_GCC_URL,
    DEFENDERATP_RESOURCE_URL,
    DEFENDERATP_SERVER_TOKEN_URL,
)


def get_environment_urls(asset) -> tuple[str, str, str]:
    """Return login, resource, and API URLs for the configured Azure environment."""
    if asset.environment == "GCC":
        return (
            DEFENDERATP_LOGIN_BASE_URL,
            DEFENDERATP_RESOURCE_GCC_URL,
            DEFENDERATP_MSGRAPH_API_GCC_BASE_URL,
        )
    if asset.environment == "GCC High":
        return (
            DEFENDERATP_LOGIN_GCC_HIGH_BASE_URL,
            DEFENDERATP_RESOURCE_GCC_HIGH_URL,
            DEFENDERATP_MSGRAPH_API_GCC_HIGH_BASE_URL,
        )
    return (
        DEFENDERATP_LOGIN_BASE_URL,
        DEFENDERATP_RESOURCE_URL,
        DEFENDERATP_MSGRAPH_API_BASE_URL,
    )


def _valid_domain(value: str) -> bool:
    if not value or len(value) > 253:
        return False
    labels = value.rstrip(".").split(".")
    return all(
        0 < len(label) <= 63
        and re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?", label)
        for label in labels
    )


def encode_domain(value: str) -> str:
    """Validate a single domain indicator before inserting it into an API path."""
    if not isinstance(value, str) or not _valid_domain(value):
        raise ValueError("Invalid domain name")
    return quote(value, safe="")


def _validate_path_segments(path: str) -> list[str]:
    """Decode path segments and reject traversal or encoded separators."""
    segments = []
    for raw_segment in path.split("/"):
        segment = raw_segment
        for _ in range(4):
            decoded = unquote(segment)
            if decoded == segment:
                break
            segment = decoded
        if (
            segment in {".", ".."}
            or "/" in segment
            or "\\" in segment
            or any(ord(char) < 32 or ord(char) == 127 for char in segment)
        ):
            raise ValueError(
                "Invalid Defender API path: path segments cannot contain traversal or separators"
            )
        segments.append(segment)
    return segments


def validate_defender_request_url(
    url: str, *, allow_computer_name: bool = False
) -> str:
    """Validate and safely encode a Defender API URL before an HTTP request."""
    parsed = urlsplit(url)
    allowed_hosts = {
        "api.securitycenter.windows.com",
        "api-gcc.securitycenter.microsoft.us",
        "api-gov.securitycenter.microsoft.us",
    }
    if (
        parsed.scheme != "https"
        or parsed.hostname not in allowed_hosts
        or parsed.username
        or parsed.password
        or parsed.port not in (None, 443)
        or parsed.fragment
    ):
        raise ValueError("Invalid Defender API request URL")

    segments = _validate_path_segments(parsed.path)
    if len(segments) < 2 or segments[1] != "api":
        raise ValueError("Invalid Defender API path: expected the /api/ prefix")

    for index, segment in enumerate(segments[:-1]):
        value = segments[index + 1]
        if segment == "machines":
            is_machine_id = re.fullmatch(r"[0-9a-f]{40}", value) is not None
            is_computer_name = allow_computer_name and _valid_domain(value)
            if not (is_machine_id or is_computer_name):
                raise ValueError(
                    "Invalid device ID: expected 40 lowercase hexadecimal characters"
                )
        elif segment == "machineactions":
            if not re.fullmatch(r"[A-Za-z0-9-]+", value):
                raise ValueError(
                    "Invalid action ID: only letters, digits, and hyphens are allowed"
                )
        elif segment == "files":
            if not re.fullmatch(
                r"(?i)(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})", value
            ):
                raise ValueError(
                    "Invalid file hash: expected an MD5, SHA1, or SHA256 hash"
                )
        elif segment == "domains":
            if not _valid_domain(value):
                raise ValueError("Invalid domain name")
        elif segment == "ips":
            try:
                ipaddress.ip_address(value)
            except ValueError as error:
                raise ValueError("Invalid IP address") from error
        elif segment == "alerts":
            if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
                raise ValueError("Invalid alert ID")

    encoded_path = "/".join(quote(segment, safe="") for segment in segments)
    return parsed._replace(path=encoded_path).geturl()


def get_oauth_config(asset, redirect_uri: str | None = None) -> OAuthConfig:
    """Build the OAuth configuration used by the SDK client and flows."""
    login_url, _, _ = get_environment_urls(asset)
    return OAuthConfig(
        client_id=asset.client_id,
        client_secret=asset.client_secret,
        authorization_endpoint=f"{login_url}/{quote(asset.tenant_id)}/oauth2/authorize",
        token_endpoint=f"{login_url}{DEFENDERATP_SERVER_TOKEN_URL.format(tenant_id=quote(asset.tenant_id))}",
        redirect_uri=redirect_uri,
    )


def get_oauth_client(asset, redirect_uri: str | None = None) -> SOARAssetOAuthClient:
    """Return a token client backed by the asset's encrypted auth state."""
    return SOARAssetOAuthClient(get_oauth_config(asset, redirect_uri), asset.auth_state)


def _save_token(
    asset, token_data: dict, previous_refresh_token: str | None = None
) -> OAuthToken:
    """Store a token response in SDK auth state while retaining an old refresh token."""
    if previous_refresh_token and not token_data.get("refresh_token"):
        token_data["refresh_token"] = previous_refresh_token
    token = OAuthToken.model_validate(token_data)
    state_data = dict(asset.auth_state.get_all())
    oauth_state = OAuthState.model_validate(state_data.get("oauth", {}))
    oauth_state.token = token
    oauth_state.client_id = asset.client_id
    state_data["oauth"] = oauth_state.model_dump(mode="json", exclude_none=True)
    asset.auth_state.put_all(state_data)
    return token


def get_access_token(asset) -> str:
    """Return a usable bearer token, refreshing the legacy Azure v1 resource grant."""
    _, resource_url, _ = get_environment_urls(asset)

    if asset.non_interactive:
        config = get_oauth_config(asset)
        flow = ClientCredentialsFlow(
            asset.auth_state,
            client_id=asset.client_id,
            client_secret=asset.client_secret,
            token_endpoint=config.token_endpoint,
            extra_params={"resource": resource_url},
        )
        return flow.get_token().access_token

    client = get_oauth_client(asset)
    try:
        token = client.get_valid_token(auto_refresh=False)
        return token.access_token
    except AuthorizationRequiredError:
        pass
    except TokenExpiredError:
        token = client.get_stored_token()
        if token and token.refresh_token:
            response = httpx.post(
                client.config.token_endpoint,
                data={
                    "grant_type": "refresh_token",
                    "client_id": asset.client_id,
                    "client_secret": asset.client_secret,
                    "refresh_token": token.refresh_token,
                    "resource": resource_url,
                },
                timeout=30.0,
            )
            response.raise_for_status()
            return _save_token(asset, response.json(), token.refresh_token).access_token
        raise

    raise AuthorizationRequiredError(
        "Run test connectivity and complete the Microsoft authorization flow first."
    )


def refresh_access_token(asset) -> str:
    """Force one fresh token after Defender rejects the current bearer token."""

    _, resource_url, _ = get_environment_urls(asset)
    if asset.non_interactive:
        config = get_oauth_config(asset)
        flow = ClientCredentialsFlow(
            asset.auth_state,
            client_id=asset.client_id,
            client_secret=asset.client_secret,
            token_endpoint=config.token_endpoint,
            extra_params={"resource": resource_url},
        )
        return flow.authenticate().access_token

    client = get_oauth_client(asset)
    token = client.get_stored_token()
    if not token or not token.refresh_token:
        raise AuthorizationRequiredError(
            "The Microsoft authorization token was rejected. Run test connectivity to authorize again."
        )
    response = httpx.post(
        client.config.token_endpoint,
        data={
            "grant_type": "refresh_token",
            "client_id": asset.client_id,
            "client_secret": asset.client_secret,
            "refresh_token": token.refresh_token,
            "resource": resource_url,
        },
        timeout=30.0,
    )
    response.raise_for_status()
    return _save_token(asset, response.json(), token.refresh_token).access_token


def authenticated_request(
    asset,
    method: str,
    url: str,
    *,
    params=None,
    json_body=None,
    data=None,
    content=None,
    headers=None,
    timeout: float = 60.0,
    verify: bool = True,
    allow_computer_name: bool = False,
):
    """Send an authenticated request, refreshing and retrying once on HTTP 401."""

    url = validate_defender_request_url(url, allow_computer_name=allow_computer_name)
    request_headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    request_headers["Authorization"] = f"Bearer {get_access_token(asset)}"

    request_kwargs = {
        "params": params,
        "json": json_body,
        "data": data,
        "content": content,
        "headers": request_headers,
        "timeout": timeout,
        "verify": verify,
    }
    response = httpx.request(
        method.upper(),
        url,
        **request_kwargs,
    )
    if response.status_code == 401:
        request_headers["Authorization"] = f"Bearer {refresh_access_token(asset)}"
        response = httpx.request(method.upper(), url, **request_kwargs)
    return response


def request_json(
    asset,
    method: str,
    url: str,
    *,
    params=None,
    json_body=None,
    data=None,
    headers=None,
    allow_computer_name: bool = False,
):
    """Send an authenticated request and return decoded JSON or an empty mapping."""
    response = authenticated_request(
        asset,
        method,
        url,
        params=params,
        json_body=json_body,
        data=data,
        headers=headers,
        timeout=60.0,
        allow_computer_name=allow_computer_name,
    )
    if not response.is_success:
        try:
            body = response.json()
            detail = (
                body.get("error", {}).get("message")
                or body.get("error_description")
                or str(body)
            )
        except (ValueError, AttributeError):
            detail = response.text
        raise RuntimeError(
            f"Error from server. Status Code: {response.status_code} Data from server: {detail}"
        )
    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError as error:
        raise RuntimeError(
            f"Invalid JSON response from Defender. Status Code: {response.status_code}. "
            "Expected a JSON response body."
        ) from error


def failed_action_result(
    message: str, params, *, data=None, summary=None
) -> ActionResult:
    """Return a failed result with any data and summary already recorded by legacy flows."""
    result = ActionResult(
        status=False,
        message=message,
        param=params.model_dump(by_alias=True, exclude_none=True) if params else None,
    )
    if data is not None:
        records = data if isinstance(data, list) else [data]
        for record in records:
            result.add_data(
                record.model_dump(by_alias=True)
                if isinstance(record, ActionOutput)
                else record
            )
    if summary is not None:
        if isinstance(summary, ActionOutput):
            summary = summary.model_dump(by_alias=True, exclude_none=True)
        result.set_summary(summary)
    return result


def odata_string_literal(value: str) -> str:
    """Return a quoted OData string literal with apostrophes escaped."""
    return "'" + value.replace("'", "''") + "'"
