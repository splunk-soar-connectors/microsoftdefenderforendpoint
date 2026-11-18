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
"""Shared helpers for Defender live response actions."""

import gzip
import os
import re
import time
from urllib.parse import unquote, urlparse

import httpx

from .consts import (
    DEFENDERATP_LIVE_RESPONSE_RESULT_ENDPOINT,
    DEFENDERATP_MACHINEACTIONS_ENDPOINT,
    DEFENDERATP_STATUS_CHECK_SLEEP,
    DEFENDERATP_STATUS_FAILED,
    DEFENDERATP_STATUS_PENDING,
    DEFENDERATP_STATUS_PROGRESS,
    DEFENDERATP_STATUS_SUCCESS,
)
from .helper import request_json


class LiveResponseEventError(ValueError):
    """A live-response event lookup failed after returning an event record."""

    def __init__(self, message: str, response: dict | None = None) -> None:
        self.response = response
        super().__init__(message)


def validate_timeout(value, default: int, maximum: int | None = None) -> int:
    """Validate a non-negative integer timeout and optionally cap it."""
    raw_value = default if value is None else value
    try:
        numeric_value = float(raw_value)
        timeout = int(numeric_value)
        if numeric_value != timeout or timeout < 0:
            raise ValueError
    except (TypeError, ValueError) as error:
        raise ValueError(
            "Invalid timeout action parameter. Must be a non-negative integer."
        ) from error
    return min(timeout, maximum) if maximum is not None else timeout


def poll_machine_action(asset, graph_url: str, action_id: str, timeout: int) -> dict:
    """Poll a machine action every five seconds, returning the last response."""
    iterations = max(
        1,
        max(timeout, DEFENDERATP_STATUS_CHECK_SLEEP) // DEFENDERATP_STATUS_CHECK_SLEEP,
    )
    response = {}
    for _ in range(iterations):
        time.sleep(DEFENDERATP_STATUS_CHECK_SLEEP)
        response = request_json(
            asset,
            "GET",
            f"{graph_url}{DEFENDERATP_MACHINEACTIONS_ENDPOINT.format(action_id=action_id)}",
        )
        if response.get("status") not in (
            DEFENDERATP_STATUS_PROGRESS,
            DEFENDERATP_STATUS_PENDING,
        ):
            break
    return response


def validate_live_response_event(
    asset, graph_url: str, event_id: str, command: str
) -> dict:
    """Ensure the event completed successfully and belongs to the requested command."""
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_MACHINEACTIONS_ENDPOINT.format(action_id=event_id)}",
    )
    commands = response.get("commands") or []
    command_type = None
    if commands:
        if not isinstance(commands, list) or not isinstance(commands[0], dict):
            raise LiveResponseEventError(
                f"The event does not contain a valid {command} command", response
            )
        command_data = commands[0].get("command") or {}
        if not isinstance(command_data, dict):
            raise LiveResponseEventError(
                f"The event does not contain a valid {command} command", response
            )
        command_type = command_data.get("type")
    if command_type != command:
        raise LiveResponseEventError(
            f"The given event_id does not correspond to {command} command", response
        )
    status = response.get("status")
    if status == DEFENDERATP_STATUS_FAILED:
        raise LiveResponseEventError(
            f"The given event_id has failed with status '{status}'", response
        )
    if status != DEFENDERATP_STATUS_SUCCESS:
        raise LiveResponseEventError(
            f"Event id status: '{status}'. The status of event_id must be 'Succeeded' in order to execute the action",
            response,
        )
    return response


def _is_allowed_download_url(value: str, environment: str) -> bool:
    try:
        parsed_url = urlparse(value)
        port = parsed_url.port
    except ValueError:
        return False
    if (
        parsed_url.scheme != "https"
        or parsed_url.username
        or parsed_url.password
        or port not in (None, 443)
    ):
        return False
    hostname = (parsed_url.hostname or "").lower()
    if environment == "Public":
        return hostname == "core.windows.net" or hostname.endswith(
            ".blob.core.windows.net"
        )
    return hostname == "core.usgovcloudapi.net" or hostname.endswith(
        ".blob.core.usgovcloudapi.net"
    )


def fetch_live_response_result(asset, graph_url: str, action_id: str):
    """Fetch a result response after checking the signed URL host and scheme."""
    response = request_json(
        asset,
        "GET",
        f"{graph_url}{DEFENDERATP_LIVE_RESPONSE_RESULT_ENDPOINT.format(action_id=action_id)}",
    )
    download_url = response.get("value")
    if not download_url:
        raise RuntimeError("No result found for live response action")
    if not _is_allowed_download_url(download_url, asset.environment):
        raise ValueError("Microsoft Defender returned an invalid download URL")

    download = httpx.get(download_url, follow_redirects=False, timeout=30.0)
    if download.status_code != 200:
        raise RuntimeError("No result found for live response action")
    return download


def download_live_response_result(asset, graph_url: str, action_id: str):
    """Download a result file and extract its filename and bytes."""
    download = fetch_live_response_result(asset, graph_url, action_id)
    disposition = download.headers.get("Content-Disposition") or ""
    match = re.search(r"filename=(.+)", disposition)
    if not match:
        raise RuntimeError("Error occurred while getting the file name")
    file_name = unquote(match.group(1).strip().strip('"').rsplit(".gz", 1)[0])
    return file_name, download.content


def add_live_response_file_to_vault(soar, file_name: str, content: bytes) -> str:
    """Store the downloaded file in the executing container's vault."""
    if not file_name or not content:
        raise ValueError("Unable to add the file to vault")
    # Preserve basename's empty result for paths ending in a separator.
    safe_name = os.path.basename(str(file_name).replace("\x00", ""))  # noqa: PTH119
    if safe_name in {"", ".", ".."}:
        raise ValueError("Invalid file name")
    try:
        file_content = gzip.decompress(content)
    except (OSError, EOFError):
        file_content = content
    return soar.vault.create_attachment(
        container_id=soar.get_executing_container_id(),
        file_content=file_content,
        file_name=safe_name,
    )
