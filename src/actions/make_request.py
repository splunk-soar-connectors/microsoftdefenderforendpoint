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
"""Make an authenticated request to a Microsoft Defender for Endpoint API."""

import json
from urllib.parse import parse_qsl, urlsplit

import httpx

from soar_sdk.action_results import MakeRequestOutput
from soar_sdk.exceptions import ActionFailure
from soar_sdk.params import MakeRequestParams, Param

from ..app import Asset, app
from ..helper import (
    authenticated_request,
    get_environment_urls,
    validate_defender_request_url,
)

DEFAULT_TIMEOUT_SECONDS = 30
MAX_TIMEOUT_SECONDS = 300
FORBIDDEN_HEADERS = {
    "authorization",
    "connection",
    "content-length",
    "host",
    "proxy-authorization",
    "transfer-encoding",
}


class DefenderMakeRequestParams(MakeRequestParams):
    endpoint: str = Param(
        description=(
            "Path relative to the Defender API root, such as '/alerts' or '/machines'. "
            "Do not include the host or '/api' prefix."
        ),
        required=True,
    )


def _get_endpoint(endpoint: str, api_root: str) -> str:
    endpoint = endpoint.strip()
    parsed = urlsplit(endpoint)
    if (
        not endpoint
        or parsed.scheme
        or parsed.netloc
        or parsed.query
        or parsed.fragment
        or "\\" in endpoint
        or endpoint.startswith("//")
    ):
        raise ActionFailure(
            "endpoint must be a relative path under the Defender API root"
        )
    endpoint = endpoint if endpoint.startswith("/") else f"/{endpoint}"
    if endpoint.startswith("/api/") or endpoint == "/api":
        raise ActionFailure(
            "endpoint is relative to the Defender API root; omit the '/api' prefix"
        )
    full_url = f"{api_root}{endpoint}"
    try:
        return validate_defender_request_url(full_url)
    except ValueError as error:
        raise ActionFailure(str(error)) from error


def _get_headers(params: DefenderMakeRequestParams) -> dict[str, str]:
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if not params.headers:
        return headers
    try:
        parsed = json.loads(params.headers)
    except (json.JSONDecodeError, TypeError) as error:
        raise ActionFailure("headers must be a JSON object") from error
    if not isinstance(parsed, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in parsed.items()
    ):
        raise ActionFailure("headers must be a JSON object with string keys and values")
    for key, value in parsed.items():
        if key.lower() in FORBIDDEN_HEADERS:
            raise ActionFailure(f"The '{key}' header cannot be overridden")
        existing_key = next(
            (name for name in headers if name.lower() == key.lower()), key
        )
        headers[existing_key] = value
    return headers


def _get_query_parameters(params: DefenderMakeRequestParams):
    if not params.query_parameters:
        return None
    try:
        parsed = json.loads(params.query_parameters)
    except (json.JSONDecodeError, TypeError) as error:
        raw_query = params.query_parameters.lstrip("?")
        if "#" in raw_query:
            raise ActionFailure("query_parameters cannot contain a fragment") from error
        return parse_qsl(raw_query, keep_blank_values=True)
    if not isinstance(parsed, dict) or not all(isinstance(key, str) for key in parsed):
        raise ActionFailure("query_parameters must be a JSON object or query string")
    return parsed


def _get_body(params: DefenderMakeRequestParams, headers: dict[str, str]):
    if params.body is None or params.body == "":
        return None, None
    content_type = next(
        (value for key, value in headers.items() if key.lower() == "content-type"),
        "",
    )
    if "json" not in content_type.lower():
        return None, params.body
    try:
        return json.loads(params.body), None
    except (json.JSONDecodeError, TypeError) as error:
        raise ActionFailure(
            "body must contain valid JSON when Content-Type is JSON"
        ) from error


@app.make_request()
def make_request(
    params: DefenderMakeRequestParams,
    asset: Asset,
) -> MakeRequestOutput:
    """Send a custom authenticated request to the configured Defender API environment."""
    method = params.http_method.upper()
    if method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}:
        raise ActionFailure("Unsupported HTTP method")
    raw_timeout = DEFAULT_TIMEOUT_SECONDS if params.timeout is None else params.timeout
    try:
        timeout = int(raw_timeout)
        if (
            isinstance(raw_timeout, bool)
            or float(raw_timeout) != timeout
            or not 1 <= timeout <= MAX_TIMEOUT_SECONDS
        ):
            raise ValueError
    except (TypeError, ValueError, OverflowError) as error:
        raise ActionFailure(
            f"timeout must be an integer from 1 to {MAX_TIMEOUT_SECONDS} seconds"
        ) from error

    _, _, api_root = get_environment_urls(asset)
    url = _get_endpoint(params.endpoint, api_root)
    headers = _get_headers(params)
    query_parameters = _get_query_parameters(params)
    json_body, content = _get_body(params, headers)
    try:
        response = authenticated_request(
            asset,
            method,
            url,
            params=query_parameters,
            json_body=json_body,
            content=content,
            headers=headers,
            timeout=timeout,
            verify=params.verify_ssl,
        )
    except httpx.HTTPError as error:
        raise ActionFailure(f"Request failed: {error}") from error
    return MakeRequestOutput(
        status_code=response.status_code, response_body=response.text
    )
