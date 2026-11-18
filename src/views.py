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
"""Custom action views for Microsoft Defender for Endpoint."""

from soar_sdk.action_results import ActionOutput, ActionResult, OutputField
from soar_sdk.views.template_renderer import get_template_renderer, get_templates_dir


class ListAlertsViewOutput(ActionOutput):
    computerDnsName: str | None = None
    id: str | None = OutputField(cef_types=["defender atp alert id"])
    title: str | None = None
    threatFamilyName: str | None = None
    status: str | None = None
    severity: str | None = None
    category: str | None = None
    alertCreationTime: str | None = None
    assignedTo: str | None = OutputField(cef_types=["email"])


class GetAlertViewOutput(ActionOutput):
    id: str | None = OutputField(cef_types=["defender atp alert id"])
    title: str | None = None
    category: str | None = None
    severity: str | None = None
    threatName: str | None = None
    computerDnsName: str | None = None
    machineId: str | None = OutputField(cef_types=["defender atp device id"])
    status: str | None = None
    assignedTo: str | None = OutputField(cef_types=["email"])
    classification: str | None = None
    determination: str | None = None


class RunScriptViewOutput(ActionOutput):
    script_output: str | None = None
    script_errors: str | None = None


def render_related_devices(
    action: str,
    all_app_runs: list[tuple[dict, list[ActionResult]]],
    context: dict,
) -> str:
    """Render related devices with legacy parameters without changing action data."""
    results = []
    for _, action_results in all_app_runs:
        for result in action_results:
            params = result.get_param() or {}
            devices = result.get_data() or []
            results.append(
                {
                    "param": params,
                    "devices": [
                        item.model_dump(by_alias=True)
                        if isinstance(item, ActionOutput)
                        else item
                        for item in devices
                    ],
                }
            )

    context["prerender"] = True
    renderer = get_template_renderer("jinja", get_templates_dir(globals()))
    return renderer.render_template("get_devices.html", {**context, "results": results})


def render_list_alerts(output: list[ListAlertsViewOutput]) -> dict:
    """Prepare alert rows for the custom widget."""
    return {
        "rows": [
            {
                "computerDnsName": item.computerDnsName,
                "id": item.id,
                "title": item.title,
                "threatFamilyName": item.threatFamilyName,
                "status": item.status,
                "severity": item.severity,
                "category": item.category,
                "alertCreationTime": item.alertCreationTime,
                "assignedTo": item.assignedTo,
            }
            for item in output
        ]
    }


def render_get_alert(output: list[GetAlertViewOutput]) -> dict:
    """Prepare alert details for the custom widget."""
    return {
        "rows": [
            {
                "id": item.id,
                "title": item.title,
                "category": item.category,
                "severity": item.severity,
                "threatName": item.threatName,
                "computerDnsName": item.computerDnsName,
                "machineId": item.machineId,
            }
            for item in output
        ]
    }


def render_update_alert(output: list[GetAlertViewOutput]) -> dict:
    """Prepare updated alert details for the custom widget."""
    return {
        "rows": [
            {
                "id": item.id,
                "title": item.title,
                "status": item.status,
                "assignedTo": item.assignedTo,
                "classification": item.classification,
                "determination": item.determination,
                "category": item.category,
                "severity": item.severity,
            }
            for item in output
        ]
    }


def render_run_script(output: list[RunScriptViewOutput]) -> dict:
    """Prepare live response script output for the custom widget."""
    return {
        "rows": [
            {"script_output": item.script_output, "script_errors": item.script_errors}
            for item in output
        ]
    }
