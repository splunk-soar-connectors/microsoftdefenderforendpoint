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
"""Legacy output field metadata embedded for SDK package inclusion."""

FIELD_SCHEMAS = {
    "test_connectivity": {"data": [], "summary": []},
    "on_poll": {"data": [], "summary": []},
    "quarantine_device": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.cancellationComment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationDateTimeUtc",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationRequestor",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["win10atp2"],
            },
            {
                "data_path": "action_result.data.*.creationDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T08:50:05.8076226Z"],
            },
            {
                "data_path": "action_result.data.*.error",
                "data_type": "string",
                "example_values": ["None"],
            },
            {
                "data_path": "action_result.data.*.errorHResult",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["6925706d-3a7e-4596-b2d7-321fca9cd965"],
                "column_name": "Event ID",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.lastUpdateDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T08:50:05.8076226Z"],
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "349838747f77ec74e43ab7ca70773a41f7bfb6f2"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.requestSource",
                "data_type": "string",
                "example_values": ["PublicApi"],
            },
            {
                "data_path": "action_result.data.*.requestor",
                "data_type": "string",
                "contains": ["email"],
                "example_values": ["testuser@example.com"],
            },
            {
                "data_path": "action_result.data.*.requestorComment",
                "data_type": "string",
                "example_values": ["Selective", "test"],
            },
            {
                "data_path": "action_result.data.*.scope",
                "data_type": "string",
                "example_values": ["Full"],
            },
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "example_values": ["Succeeded"],
                "column_name": "Quarantine Status",
                "column_order": 5,
            },
            {"data_path": "action_result.data.*.title", "data_type": "string"},
            {
                "data_path": "action_result.data.*.troubleshootInfo",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.type",
                "data_type": "string",
                "example_values": ["Isolate"],
                "column_name": "Event Type",
                "column_order": 4,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.event_id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["6925706d-3a7e-4596-b2d7-321fca9cd965"],
            },
            {
                "data_path": "action_result.summary.quarantine_status",
                "data_type": "string",
                "example_values": ["Pending"],
            },
        ],
    },
    "unquarantine_device": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.cancellationComment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationDateTimeUtc",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationRequestor",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["win10atp2"],
            },
            {
                "data_path": "action_result.data.*.creationDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T08:52:22.7708738Z"],
            },
            {
                "data_path": "action_result.data.*.error",
                "data_type": "string",
                "example_values": ["None"],
            },
            {
                "data_path": "action_result.data.*.errorHResult",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["cb15e6e0-1d53-4762-9c37-f14d412ece9e"],
                "column_name": "Event ID",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.lastUpdateDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T08:52:22.7708738Z"],
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "349838747f77ec74e43ab7ca70773a41f7bfb6f2"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.requestSource",
                "data_type": "string",
                "example_values": ["PublicApi"],
            },
            {
                "data_path": "action_result.data.*.requestor",
                "data_type": "string",
                "contains": ["email"],
                "example_values": ["testuser@example.com"],
            },
            {
                "data_path": "action_result.data.*.requestorComment",
                "data_type": "string",
                "example_values": ["isolation", "test"],
            },
            {"data_path": "action_result.data.*.scope", "data_type": "string"},
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "example_values": ["Pending"],
                "column_name": "Unquarantine Status",
                "column_order": 4,
            },
            {"data_path": "action_result.data.*.title", "data_type": "string"},
            {
                "data_path": "action_result.data.*.troubleshootInfo",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.type",
                "data_type": "string",
                "example_values": ["Unisolate"],
                "column_name": "Event Type",
                "column_order": 3,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.event_id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["cb15e6e0-1d53-4762-9c37-f14d412ece9e"],
            },
            {
                "data_path": "action_result.summary.unquarantine_status",
                "data_type": "string",
                "example_values": ["Pending"],
            },
        ],
    },
    "get_status": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.cancellationComment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationDateTimeUtc",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationRequestor",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.commands.*.command.params.*.key",
                "data_type": "string",
                "example_values": ["Path"],
            },
            {
                "data_path": "action_result.data.*.commands.*.command.params.*.value",
                "data_type": "string",
                "example_values": ["C:\\share\\1.eml"],
            },
            {
                "data_path": "action_result.data.*.commands.*.command.type",
                "data_type": "string",
                "example_values": ["GetFile"],
            },
            {
                "data_path": "action_result.data.*.commands.*.commandStatus",
                "data_type": "string",
                "example_values": ["Created"],
            },
            {
                "data_path": "action_result.data.*.commands.*.endTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.commands.*.index",
                "data_type": "numeric",
            },
            {
                "data_path": "action_result.data.*.commands.*.startTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["win10atp2"],
            },
            {
                "data_path": "action_result.data.*.creationDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T09:01:19.3478911Z"],
            },
            {
                "data_path": "action_result.data.*.error",
                "data_type": "string",
                "example_values": ["None"],
            },
            {
                "data_path": "action_result.data.*.errorHResult",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {"data_path": "action_result.data.*.fileInstances", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["f4ddc97a-6f4e-471c-9be5-45e0d6d64ab8"],
            },
            {
                "data_path": "action_result.data.*.lastUpdateDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T09:01:27.6955788Z"],
                "column_name": "Last Update Time",
                "column_order": 6,
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "ae2e5bda4bb22ec9c321680079d03e5e4cdff400"  # pragma: allowlist secret
                ],
                "column_name": "Device ID",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.relatedFileInfo.fileIdentifier",
                "data_type": "string",
                "contains": ["sha1"],
                "example_values": [
                    "2dba4c14a5e97312f9edf617e1c8b0cc0d387fd8"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.relatedFileInfo.fileIdentifierType",
                "data_type": "string",
                "example_values": ["Sha1"],
            },
            {
                "data_path": "action_result.data.*.requestSource",
                "data_type": "string",
                "example_values": ["PublicApi"],
            },
            {
                "data_path": "action_result.data.*.requestor",
                "data_type": "string",
                "contains": ["email"],
                "example_values": ["test.user@example.onmicrosoft.com"],
                "column_name": "Requestor",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.requestorComment",
                "data_type": "string",
                "example_values": ["test"],
                "column_name": "Comment",
                "column_order": 5,
            },
            {"data_path": "action_result.data.*.scope", "data_type": "string"},
            {
                "data_path": "action_result.data.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
                "example_values": [
                    "11ffeabbe42159e1365aa82463d8690c845ce7b7"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "example_values": ["Succeeded"],
                "column_name": "Event Status",
                "column_order": 2,
            },
            {"data_path": "action_result.data.*.title", "data_type": "string"},
            {
                "data_path": "action_result.data.*.troubleshootInfo",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.type",
                "data_type": "string",
                "example_values": ["RunAntiVirusScan"],
                "column_name": "Event Type",
                "column_order": 1,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.event_status",
                "data_type": "string",
                "example_values": ["Succeeded"],
            }
        ],
    },
    "scan_device": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.cancellationComment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationDateTimeUtc",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationRequestor",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["win10atp2"],
            },
            {
                "data_path": "action_result.data.*.creationDateTimeUtc",
                "data_type": "string",
                "example_values": ["2018-07-12T11:35:30.8573959Z"],
                "column_name": "Creation Time",
                "column_order": 7,
            },
            {
                "data_path": "action_result.data.*.error",
                "data_type": "string",
                "example_values": ["None"],
            },
            {
                "data_path": "action_result.data.*.errorHResult",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["34a0905e-316b-46eb-994d-c7d0e8ac2efb"],
                "column_name": "Event ID",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.lastUpdateDateTimeUtc",
                "data_type": "string",
                "example_values": ["2018-07-12T11:35:30.8573959Z"],
                "column_name": "Last Update Time",
                "column_order": 6,
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "a3627cbcad1e9ca2dd94eed63e3f9260e2aa7e8e"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.requestSource",
                "data_type": "string",
                "example_values": ["PublicApi"],
            },
            {
                "data_path": "action_result.data.*.requestor",
                "data_type": "string",
                "contains": ["email"],
                "example_values": ["testuser@example.com"],
                "column_name": "Requestor",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.requestorComment",
                "data_type": "string",
                "example_values": ["From Test"],
            },
            {
                "data_path": "action_result.data.*.scope",
                "data_type": "string",
                "example_values": ["Quick"],
            },
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "example_values": ["InProgress"],
                "column_name": "Scan Status",
                "column_order": 3,
            },
            {"data_path": "action_result.data.*.title", "data_type": "string"},
            {
                "data_path": "action_result.data.*.troubleshootInfo",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.type",
                "data_type": "string",
                "example_values": ["RunAntiVirusScan"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.event_id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["34a0905e-316b-46eb-994d-c7d0e8ac2efb"],
            },
            {
                "data_path": "action_result.summary.scan_status",
                "data_type": "string",
                "example_values": ["InProgress"],
            },
        ],
    },
    "quarantine_file": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.cancellationComment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationDateTimeUtc",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationRequestor",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["win10atp2"],
            },
            {
                "data_path": "action_result.data.*.creationDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T06:00:00.2740597Z"],
            },
            {
                "data_path": "action_result.data.*.error",
                "data_type": "string",
                "example_values": ["None"],
            },
            {
                "data_path": "action_result.data.*.errorHResult",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.fileId",
                "data_type": "string",
                "contains": ["sha1"],
                "example_values": [
                    "e1049556edc2b28ef25b2932c722e4dc927e9d04"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.fileInstances.*.filePath",
                "data_type": "string",
                "contains": ["file path"],
            },
            {
                "data_path": "action_result.data.*.fileInstances.*.status",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["76e82ecd-54b8-400d-83be-a05d582b3546"],
                "column_name": "Event ID",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.lastUpdateDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T06:00:00.2740597Z"],
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "ae2e5bda4bb22ec9c321680079d03e5e4cdff400"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.relatedFileInfo.fileIdentifier",
                "data_type": "string",
                "contains": ["sha1"],
                "example_values": [
                    "2dba4c14a5e97312f9edf617e1c8b0cc0d387fd8"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.relatedFileInfo.fileIdentifierType",
                "data_type": "string",
                "example_values": ["Sha1"],
            },
            {
                "data_path": "action_result.data.*.requestSource",
                "data_type": "string",
                "example_values": ["PublicApi"],
            },
            {
                "data_path": "action_result.data.*.requestor",
                "data_type": "string",
                "contains": ["email"],
                "example_values": ["testuser@example.com"],
            },
            {
                "data_path": "action_result.data.*.requestorComment",
                "data_type": "string",
                "example_values": ["file quarantine"],
            },
            {"data_path": "action_result.data.*.scope", "data_type": "string"},
            {
                "data_path": "action_result.data.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
                "example_values": [
                    "e1049556edc2b28ef25b2932c722e4dc927e9d04"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "example_values": ["Pending"],
                "column_name": "Quarantine Status",
                "column_order": 5,
            },
            {"data_path": "action_result.data.*.title", "data_type": "string"},
            {
                "data_path": "action_result.data.*.troubleshootInfo",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.type",
                "data_type": "string",
                "example_values": ["StopAndQuarantineFile"],
                "column_name": "Event Type",
                "column_order": 4,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.event_id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["76e82ecd-54b8-400d-83be-a05d582b3546"],
            },
            {
                "data_path": "action_result.summary.quarantine_status",
                "data_type": "string",
                "example_values": ["InProgress"],
            },
        ],
    },
    "get_active_users": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp user id"],
                "column_name": "User ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.accountName",
                "data_type": "string",
                "column_name": "Account Name",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.accountDomain",
                "data_type": "string",
                "column_name": "Account Domain",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.firstSeen",
                "data_type": "string",
                "column_name": "First Seen",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.lastSeen",
                "data_type": "string",
                "column_name": "Last Seen",
                "column_order": 4,
            },
            {"data_path": "action_result.data.*.logonTypes", "data_type": "string"},
            {"data_path": "action_result.data.*.isDomainAdmin", "data_type": "boolean"},
            {
                "data_path": "action_result.data.*.isOnlyNetworkUser",
                "data_type": "boolean",
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_results",
                "data_type": "numeric",
            },
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Active Users"],
            },
        ],
    },
    "list_devices": {
        "data": [
            {"data_path": "action_result.data.*.aadDeviceId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.agentVersion",
                "data_type": "string",
                "example_values": ["10.5850.17763.404"],
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "contains": ["domain"],
                "example_values": ["desktop-ph2a1ro"],
                "column_name": "Computer Name",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.defenderAvStatus",
                "data_type": "string",
                "example_values": ["NotSupported"],
            },
            {
                "data_path": "action_result.data.*.deviceValue",
                "data_type": "string",
                "example_values": ["Normal"],
            },
            {
                "data_path": "action_result.data.*.exposureLevel",
                "data_type": "string",
                "example_values": ["Medium"],
            },
            {
                "data_path": "action_result.data.*.firstSeen",
                "data_type": "string",
                "example_values": ["2019-04-16T00:27:12.2677222Z"],
            },
            {"data_path": "action_result.data.*.groupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.healthStatus",
                "data_type": "string",
                "example_values": ["Active"],
                "column_name": "Health Status",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "ae2e5bda4bb22ec9c321680079d03e5e4cdff400"  # pragma: allowlist secret
                ],
                "column_name": "Device ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.ipAddress",
                "data_type": "string",
                "example_values": ["10.0.2.15"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.macAddress",
                "data_type": "string",
                "example_values": [
                    "002248242A86"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.operationalStatus",
                "data_type": "string",
                "example_values": ["Up"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.type",
                "data_type": "string",
                "example_values": ["Ethernet"],
            },
            {
                "data_path": "action_result.data.*.isAadJoined",
                "data_type": "boolean",
                "example_values": [True, False],
            },
            {
                "data_path": "action_result.data.*.lastExternalIpAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["204.107.141.240"],
                "column_name": "Last External IP Address",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.lastIpAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["10.1.66.140"],
                "column_name": "Last IP Address",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.lastSeen",
                "data_type": "string",
                "example_values": ["2019-05-03T05:23:45.9643247Z"],
            },
            {
                "data_path": "action_result.data.*.machineTags",
                "data_type": "string",
                "example_values": ["Test Tag -21"],
            },
            {"data_path": "action_result.data.*.managedBy", "data_type": "string"},
            {
                "data_path": "action_result.data.*.managedByStatus",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.onboardingStatus",
                "data_type": "string",
                "example_values": ["Onboarded"],
            },
            {
                "data_path": "action_result.data.*.osArchitecture",
                "data_type": "string",
                "example_values": ["64-bit"],
            },
            {
                "data_path": "action_result.data.*.osBuild",
                "data_type": "numeric",
                "example_values": [17763],
            },
            {
                "data_path": "action_result.data.*.osPlatform",
                "data_type": "string",
                "example_values": ["Windows10"],
                "column_name": "OS",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.osProcessor",
                "data_type": "string",
                "example_values": ["x64"],
            },
            {"data_path": "action_result.data.*.osVersion", "data_type": "string"},
            {
                "data_path": "action_result.data.*.rbacGroupId",
                "data_type": "numeric",
                "example_values": [0],
            },
            {
                "data_path": "action_result.data.*.rbacGroupName",
                "data_type": "string",
                "example_values": ["GROUP1"],
            },
            {
                "data_path": "action_result.data.*.riskScore",
                "data_type": "string",
                "example_values": ["None"],
            },
            {
                "data_path": "action_result.data.*.systemProductName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.version",
                "data_type": "string",
                "example_values": ["1809"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.cloudProvider",
                "data_type": "string",
                "example_values": ["Azure"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.resourceId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.vmMetadata.subscriptionId",
                "data_type": "string",
                "example_values": ["1b922e46-8595-4749-997a-1205e714cd91"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.vmId",
                "data_type": "string",
                "example_values": ["79980585-d655-43f7-80d9-5b9d34b2e30d"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_devices",
                "data_type": "numeric",
                "example_values": [2],
            }
        ],
    },
    "list_alerts": {
        "data": [
            {
                "data_path": "action_result.data.*.aadTenantId",
                "data_type": "string",
                "example_values": ["7810-b62a-4fc0-bbbb-20165d183d7f"],
            },
            {
                "data_path": "action_result.data.*.alertCreationTime",
                "data_type": "string",
                "example_values": ["2019-05-03T01:20:51.8699882Z"],
            },
            {
                "data_path": "action_result.data.*.assignedTo",
                "data_type": "string",
                "contains": ["email"],
                "example_values": ["testuser@example.com"],
            },
            {
                "data_path": "action_result.data.*.category",
                "data_type": "string",
                "example_values": ["General"],
            },
            {"data_path": "action_result.data.*.classification", "data_type": "string"},
            {
                "data_path": "action_result.data.*.comments.*.comment",
                "data_type": "string",
                "example_values": ["test"],
            },
            {
                "data_path": "action_result.data.*.comments.*.createdBy",
                "data_type": "string",
                "contains": ["email"],
                "example_values": ["test@example.onmicrosoft.com"],
            },
            {
                "data_path": "action_result.data.*.comments.*.createdTime",
                "data_type": "string",
                "example_values": ["2019-05-01T13:21:37.869889Z"],
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["win10atp1"],
            },
            {
                "data_path": "action_result.data.*.description",
                "data_type": "string",
                "example_values": [
                    "Malware and unwanted software are undesirable applications that perform "
                    "annoying, disruptive, or harmful actions on affected machines. Some of "
                    "these undesirable applications can replicate and spread from one "
                    "machine to another. Others can able to receive commands from remote "
                    "attackers and perform activities associated with cyber attacks. This "
                    "detection might indicate that Windows Defender has stopped the malware "
                    "from delivering its payload. However, it is prudent to check the "
                    "machine for signs of infection."
                ],
            },
            {
                "data_path": "action_result.data.*.detectionSource",
                "data_type": "string",
                "example_values": ["WindowsDefenderAv"],
            },
            {
                "data_path": "action_result.data.*.detectorId",
                "data_type": "string",
                "example_values": ["5c6b7d86-c91f-4f8c-8aec-9d2086f46527"],
            },
            {"data_path": "action_result.data.*.determination", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.aadUserId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.detectionStatus",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.domainName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.entityType",
                "data_type": "string",
                "example_values": ["Url"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.evidenceCreationTime",
                "data_type": "string",
                "example_values": ["2022-06-10T06:26:09.5133333Z"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.fileName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.filePath",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.ipAddress",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFileName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFilePath",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCommandLine",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryHive",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryKey",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValue",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha1",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha256",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.url",
                "data_type": "string",
                "example_values": ["google.com"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.userPrincipalName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.userSid",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.firstEventTime",
                "data_type": "string",
                "example_values": ["2019-05-02T23:03:43.2077683Z"],
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp alert id"],
                "example_values": ["636924432519012302_1685044642"],
            },
            {
                "data_path": "action_result.data.*.incidentId",
                "data_type": "numeric",
                "example_values": [11],
            },
            {
                "data_path": "action_result.data.*.investigationId",
                "data_type": "numeric",
                "example_values": [10],
            },
            {
                "data_path": "action_result.data.*.investigationState",
                "data_type": "string",
                "example_values": ["Benign"],
            },
            {
                "data_path": "action_result.data.*.lastEventTime",
                "data_type": "string",
                "example_values": ["2019-05-02T23:03:43.2077683Z"],
            },
            {
                "data_path": "action_result.data.*.lastUpdateTime",
                "data_type": "string",
                "example_values": ["2019-05-03T01:29:51.9233333Z"],
            },
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.accountName",
                "data_type": "string",
                "example_values": ["Test"],
            },
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.domainName",
                "data_type": "string",
                "example_values": ["WINATPC1"],
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "ae2e5bda4bb22ec9c321680079d03e5e4cdff400"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.rbacGroupName",
                "data_type": "string",
                "example_values": ["UnassignedGroup"],
            },
            {
                "data_path": "action_result.data.*.recommendedAction",
                "data_type": "string",
                "example_values": [
                    "Collect artifacts and determine scope Review the machine timeline for "
                    "suspicious activities that may have occurred before and after the time "
                    "of the alert, and record additional related artifacts (files, IPs/URLs) "
                    "Look for the presence of relevant artifacts on other systems. Identify "
                    "commonalities and differences between potentially compromised systems. "
                    "Submit relevant files for deep analysis and review resulting in "
                    "detailed behavioral information. Submit undetected files to the MMPC "
                    "malware portal Initiate containment & mitigation Contact the user to "
                    "verify intent and initiate local remediation actions as needed. Update "
                    "AV signatures and run a full scan. The scan might reveal and remove "
                    "previously-undetected malware components. Ensure that the machine has "
                    "the latest security updates. In particular, ensure that you have "
                    "installed the latest software, web browser, and Operating System "
                    "versions. If credential theft is suspected, reset all relevant users' "
                    "passwords. Block communication with relevant URLs or IPs at the "
                    "organization's perimeter."
                ],
            },
            {
                "data_path": "action_result.data.*.relatedUser.domainName",
                "data_type": "string",
                "example_values": ["WINATPC1"],
            },
            {
                "data_path": "action_result.data.*.relatedUser.userName",
                "data_type": "string",
                "example_values": ["Test"],
            },
            {
                "data_path": "action_result.data.*.resolvedTime",
                "data_type": "string",
                "example_values": ["2019-05-03T01:29:51.7614303Z"],
            },
            {
                "data_path": "action_result.data.*.severity",
                "data_type": "string",
                "example_values": ["Informational"],
            },
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "example_values": ["Resolved"],
            },
            {
                "data_path": "action_result.data.*.threatFamilyName",
                "data_type": "string",
                "example_values": ["Fuery"],
            },
            {"data_path": "action_result.data.*.threatName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.title",
                "data_type": "string",
                "example_values": ["Windows Defender AV detected 'Fuery' malware"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_alerts",
                "data_type": "numeric",
                "example_values": [12],
            }
        ],
    },
    "list_sessions": {
        "data": [
            {
                "data_path": "action_result.data.*.accountDomain",
                "data_type": "string",
                "contains": ["domain"],
                "example_values": ["win10atp1"],
            },
            {
                "data_path": "action_result.data.*.accountDomainName",
                "data_type": "string",
                "contains": ["domain"],
                "example_values": ["desktop-gq5jf56"],
                "column_name": "Account Domain Name",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.accountName",
                "data_type": "string",
                "example_values": ["example"],
                "column_name": "Account Name",
                "column_order": 2,
            },
            {"data_path": "action_result.data.*.accountSid", "data_type": "string"},
            {
                "data_path": "action_result.data.*.firstSeen",
                "data_type": "string",
                "example_values": ["2018-07-06T00:00:00Z"],
                "column_name": "First Seen",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "example_values": ["desktop-gq5jf56\\example"],
                "column_name": "User ID",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.isDomainAdmin",
                "data_type": "boolean",
                "example_values": [True, False],
                "column_name": "Domain Admin",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.isOnlyNetworkUser",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.lastSeen",
                "data_type": "string",
                "example_values": ["2018-07-06T00:00:00Z"],
                "column_name": "Last Seen",
                "column_order": 6,
            },
            {
                "data_path": "action_result.data.*.leastPrevalentMachineId",
                "data_type": "string",
                "contains": ["sha1"],
            },
            {
                "data_path": "action_result.data.*.logOnMachinesCount",
                "data_type": "numeric",
                "example_values": [1],
            },
            {
                "data_path": "action_result.data.*.logonTypes",
                "data_type": "string",
                "example_values": ["Network, RemoteInteractive"],
            },
            {
                "data_path": "action_result.data.*.mostPrevalentMachineId",
                "data_type": "string",
                "contains": ["sha1"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_sessions",
                "data_type": "numeric",
                "example_values": [1],
            }
        ],
    },
    "list_software": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp software id"],
                "column_name": "Software ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.name",
                "data_type": "string",
                "column_name": "Software Name",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.vendor",
                "data_type": "string",
                "column_name": "Vendor",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.weaknesses",
                "data_type": "numeric",
                "column_name": "Weaknesses",
                "column_order": 3,
            },
            {"data_path": "action_result.data.*.publicExploit", "data_type": "numeric"},
            {"data_path": "action_result.data.*.activeAlert", "data_type": "numeric"},
            {
                "data_path": "action_result.data.*.exposedMachines",
                "data_type": "numeric",
                "column_name": "Exposed Machines",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.installedMachines",
                "data_type": "numeric",
                "column_name": "Installed Machines",
                "column_order": 5,
            },
            {"data_path": "action_result.data.*.impactScore", "data_type": "numeric"},
            {"data_path": "action_result.data.*.isNormalized", "data_type": "numeric"},
            {"data_path": "action_result.data.*.category", "data_type": "string"},
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_software",
                "data_type": "numeric",
            }
        ],
    },
    "list_software_versions": {
        "data": [
            {
                "data_path": "action_result.data.*.version",
                "data_type": "string",
                "column_name": "Version",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.installations",
                "data_type": "numeric",
                "column_name": "Installations",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.vulnerabilities",
                "data_type": "numeric",
                "column_name": "Vulnerabilities",
                "column_order": 2,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_versions",
                "data_type": "numeric",
            }
        ],
    },
    "list_software_devices": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "column_name": "Device ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "column_name": "Device Name",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.osPlatform",
                "data_type": "string",
                "column_name": "Operating System",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.rbacGroupName",
                "data_type": "string",
                "column_name": "RBAC Group Name",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.rbacGroupId",
                "data_type": "string",
                "column_name": "RBAC Group ID",
                "column_order": 4,
            },
        ],
        "summary": [
            {"data_path": "action_result.summary.total_devices", "data_type": "numeric"}
        ],
    },
    "list_software_vulnerabilities": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp vulnerability id"],
                "column_name": "Vulnerability ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.name",
                "data_type": "string",
                "column_name": "Vulnerability Name",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.description",
                "data_type": "string",
                "column_name": "Description",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.severity",
                "data_type": "string",
                "column_name": "Severity",
                "column_order": 3,
            },
            {"data_path": "action_result.data.*.cvssV3", "data_type": "numeric"},
            {
                "data_path": "action_result.data.*.exposedMachines",
                "data_type": "numeric",
                "column_name": "Exposed Machines",
                "column_order": 4,
            },
            {"data_path": "action_result.data.*.publishedOn", "data_type": "string"},
            {"data_path": "action_result.data.*.updatedOn", "data_type": "string"},
            {
                "data_path": "action_result.data.*.firstDetected",
                "data_type": "string",
                "column_name": "First Detected",
                "column_order": 5,
            },
            {"data_path": "action_result.data.*.publicExploit", "data_type": "boolean"},
            {
                "data_path": "action_result.data.*.exploitVerified",
                "data_type": "boolean",
            },
            {"data_path": "action_result.data.*.exploitInKit", "data_type": "boolean"},
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_vulnerabilities",
                "data_type": "numeric",
            }
        ],
    },
    "list_device_vulnerabilities": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp software id"],
                "column_name": "ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.cveId",
                "data_type": "string",
                "contains": ["cve id"],
                "column_name": "CVE ID",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "column_name": "Machine ID",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.productName",
                "data_type": "string",
                "column_name": "Product Name",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.productVendor",
                "data_type": "string",
                "column_name": "Product Vendor",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.productVersion",
                "data_type": "string",
                "column_name": "Product Version",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.severity",
                "data_type": "string",
                "column_name": "Severity",
                "column_order": 6,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_vulnerabilities",
                "data_type": "numeric",
            }
        ],
    },
    "list_vulnerabilities": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["cve id"],
                "column_name": "Vulnerability ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.name",
                "data_type": "string",
                "column_name": "Vulnerability Name",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.description",
                "data_type": "string",
                "column_name": "Description",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.severity",
                "data_type": "string",
                "column_name": "Severity",
                "column_order": 3,
            },
            {"data_path": "action_result.data.*.cvssV3", "data_type": "numeric"},
            {"data_path": "action_result.data.*.cvssVector", "data_type": "string"},
            {
                "data_path": "action_result.data.*.exposedMachines",
                "data_type": "numeric",
                "column_name": "Exposed Machines",
                "column_order": 4,
            },
            {"data_path": "action_result.data.*.publishedOn", "data_type": "string"},
            {"data_path": "action_result.data.*.updatedOn", "data_type": "string"},
            {
                "data_path": "action_result.data.*.firstDetected",
                "data_type": "string",
                "column_name": "First Detected",
                "column_order": 5,
            },
            {"data_path": "action_result.data.*.publicExploit", "data_type": "boolean"},
            {
                "data_path": "action_result.data.*.exploitVerified",
                "data_type": "boolean",
            },
            {"data_path": "action_result.data.*.exploitInKit", "data_type": "boolean"},
            {
                "data_path": "action_result.data.*.cveSupportability",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.epss", "data_type": "numeric"},
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_vulnerabilities",
                "data_type": "numeric",
            }
        ],
    },
    "get_alert": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#Alerts/$entity"
                ],
            },
            {"data_path": "action_result.data.*.aadTenantId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.alertCreationTime",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.assignedTo", "data_type": "string"},
            {"data_path": "action_result.data.*.category", "data_type": "string"},
            {"data_path": "action_result.data.*.classification", "data_type": "string"},
            {
                "data_path": "action_result.data.*.comments.*.comment",
                "data_type": "string",
                "example_values": ["Test"],
            },
            {
                "data_path": "action_result.data.*.comments.*.createdBy",
                "data_type": "string",
                "example_values": ["Automation"],
            },
            {
                "data_path": "action_result.data.*.comments.*.createdTime",
                "data_type": "string",
                "example_values": ["2022-04-08T18:03:45.6064942Z"],
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.description", "data_type": "string"},
            {
                "data_path": "action_result.data.*.detectionSource",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.detectorId", "data_type": "string"},
            {"data_path": "action_result.data.*.determination", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.aadUserId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.detectionStatus",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.domainName",
                "data_type": "string",
                "contains": ["domain"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.entityType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.evidenceCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.fileName",
                "data_type": "string",
                "contains": ["file name"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.filePath",
                "data_type": "string",
                "contains": ["file path"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.ipAddress",
                "data_type": "string",
                "contains": ["ip"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFileName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFilePath",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCommandLine",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryHive",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryKey",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValue",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha256",
                "data_type": "string",
                "contains": ["sha256"],
            },
            {"data_path": "action_result.data.*.evidence.*.url", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.userPrincipalName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.userSid",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.firstEventTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp alert id"],
            },
            {"data_path": "action_result.data.*.incidentId", "data_type": "numeric"},
            {
                "data_path": "action_result.data.*.investigationId",
                "data_type": "numeric",
            },
            {
                "data_path": "action_result.data.*.investigationState",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.lastEventTime", "data_type": "string"},
            {"data_path": "action_result.data.*.lastUpdateTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.accountName",
                "data_type": "string",
                "example_values": ["TestUser"],
            },
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.domainName",
                "data_type": "string",
                "example_values": ["WINATPC2"],
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
            },
            {"data_path": "action_result.data.*.rbacGroupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.relatedUser.domainName",
                "data_type": "string",
                "example_values": ["WINATPC1"],
            },
            {
                "data_path": "action_result.data.*.relatedUser.userName",
                "data_type": "string",
                "example_values": ["TestUser"],
            },
            {"data_path": "action_result.data.*.resolvedTime", "data_type": "string"},
            {"data_path": "action_result.data.*.severity", "data_type": "string"},
            {"data_path": "action_result.data.*.status", "data_type": "string"},
            {
                "data_path": "action_result.data.*.threatFamilyName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.threatName", "data_type": "string"},
            {"data_path": "action_result.data.*.title", "data_type": "string"},
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Alert"],
            }
        ],
    },
    "get_alert_user": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp user id"],
                "column_name": "User ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.accountName",
                "data_type": "string",
                "column_name": "Account Name",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.accountDomain",
                "data_type": "string",
                "column_name": "Account Domain",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.accountSid",
                "data_type": "string",
                "column_name": "Account SID",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.firstSeen",
                "data_type": "string",
                "column_name": "First Seen",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.lastSeen",
                "data_type": "string",
                "column_name": "Last Seen",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.mostPrevalentMachineId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.leastPrevalentMachineId",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.logonTypes", "data_type": "string"},
            {
                "data_path": "action_result.data.*.logOnMachinesCount",
                "data_type": "numeric",
            },
            {"data_path": "action_result.data.*.isDomainAdmin", "data_type": "boolean"},
            {
                "data_path": "action_result.data.*.isOnlyNetworkUser",
                "data_type": "boolean",
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Assigned User for Alert"],
            }
        ],
    },
    "get_alert_files": {
        "data": [
            {
                "data_path": "action_result.data.*.determinationType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.determinationValue",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.fileProductName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.filePublisher", "data_type": "string"},
            {"data_path": "action_result.data.*.fileType", "data_type": "string"},
            {"data_path": "action_result.data.*.isPeFile", "data_type": "boolean"},
            {
                "data_path": "action_result.data.*.isValidCertificate",
                "data_type": "boolean",
            },
            {
                "data_path": "action_result.data.*.size",
                "data_type": "numeric",
                "column_name": "Size",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.issuer",
                "data_type": "string",
                "column_name": "Issuer",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.globalFirstObserved",
                "data_type": "string",
                "column_name": "Global First Observed",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.globalPrevalence",
                "data_type": "numeric",
                "column_name": "Global Prevalence",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.globalLastObserved",
                "data_type": "string",
                "column_name": "Global Last Observed",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.md5",
                "data_type": "string",
                "contains": ["md5"],
                "example_values": [
                    "44adb27786eb24e5bbfd06b69e84d252"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
                "example_values": [
                    "954e0fd64a1242d0fa860b220198118268e35018"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.sha256",
                "data_type": "string",
                "contains": ["sha256"],
                "example_values": [
                    "1a563e59bfcdc9e7b4d8ac81c6b6579e2d215952f6dd98e0ab1ab026ac616896"  # pragma: allowlist secret
                ],
            },
            {"data_path": "action_result.data.*.signer", "data_type": "string"},
            {"data_path": "action_result.data.*.signerHash", "data_type": "string"},
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Files for Alert"],
            },
            {
                "data_path": "action_result.summary.total_results",
                "data_type": "numeric",
                "example_values": [1],
            },
        ],
    },
    "get_alert_ips": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["ip"],
                "column_name": "IP Address",
                "column_order": 0,
            }
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved IPs for Alert"],
            },
            {
                "data_path": "action_result.summary.total_results",
                "data_type": "numeric",
                "example_values": [5],
            },
        ],
    },
    "get_alert_domains": {
        "data": [
            {
                "data_path": "action_result.data.*.host",
                "data_type": "string",
                "contains": ["domain"],
                "column_name": "Domain",
                "column_order": 0,
            }
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Domains for Alert"],
            },
            {
                "data_path": "action_result.summary.total_results",
                "data_type": "numeric",
                "example_values": [5],
            },
        ],
    },
    "create_alert": {
        "data": [
            {"data_path": "action_result.data.*.aadTenantId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.alertCreationTime",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.assignedTo", "data_type": "string"},
            {"data_path": "action_result.data.*.category", "data_type": "string"},
            {"data_path": "action_result.data.*.classification", "data_type": "string"},
            {
                "data_path": "action_result.data.*.comments.*.comment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdBy",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.description", "data_type": "string"},
            {
                "data_path": "action_result.data.*.detectionSource",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.detectorId", "data_type": "string"},
            {"data_path": "action_result.data.*.determination", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.aadUserId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.detectionStatus",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.domainName",
                "data_type": "string",
                "contains": ["domain"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.entityType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.evidenceCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.fileName",
                "data_type": "string",
                "contains": ["file name"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.filePath",
                "data_type": "string",
                "contains": ["file path"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.ipAddress",
                "data_type": "string",
                "contains": ["ip"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFileName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFilePath",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCommandLine",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryHive",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryKey",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValue",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha256",
                "data_type": "string",
                "contains": ["sha256"],
            },
            {"data_path": "action_result.data.*.evidence.*.url", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.userPrincipalName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.userSid",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.firstEventTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp alert id"],
                "column_name": "Alert ID",
                "column_order": 0,
            },
            {"data_path": "action_result.data.*.incidentId", "data_type": "numeric"},
            {
                "data_path": "action_result.data.*.investigationId",
                "data_type": "numeric",
            },
            {
                "data_path": "action_result.data.*.investigationState",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.lastEventTime", "data_type": "string"},
            {"data_path": "action_result.data.*.lastUpdateTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.domainName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
            },
            {"data_path": "action_result.data.*.rbacGroupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.relatedUser.domainName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.relatedUser.userName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.resolvedTime", "data_type": "string"},
            {"data_path": "action_result.data.*.severity", "data_type": "string"},
            {"data_path": "action_result.data.*.status", "data_type": "string"},
            {
                "data_path": "action_result.data.*.threatFamilyName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.threatName", "data_type": "string"},
            {"data_path": "action_result.data.*.title", "data_type": "string"},
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Created Alert"],
            }
        ],
    },
    "update_alert": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
            },
            {"data_path": "action_result.data.*.aadTenantId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.alertCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.assignedTo",
                "data_type": "string",
                "contains": ["email"],
            },
            {"data_path": "action_result.data.*.category", "data_type": "string"},
            {"data_path": "action_result.data.*.classification", "data_type": "string"},
            {
                "data_path": "action_result.data.*.comments.*.comment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdBy",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.description", "data_type": "string"},
            {
                "data_path": "action_result.data.*.detectionSource",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.detectorId", "data_type": "string"},
            {"data_path": "action_result.data.*.determination", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.aadUserId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.detectionStatus",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.domainName",
                "data_type": "string",
                "contains": ["domain"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.entityType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.evidenceCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.fileName",
                "data_type": "string",
                "contains": ["file name"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.filePath",
                "data_type": "string",
                "contains": ["file path"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.ipAddress",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFileName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFilePath",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCommandLine",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryHive",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryKey",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValue",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha256",
                "data_type": "string",
                "contains": ["sha256"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.url",
                "data_type": "string",
                "contains": ["url"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.userPrincipalName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.userSid",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.firstEventTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp alert id"],
            },
            {"data_path": "action_result.data.*.incidentId", "data_type": "numeric"},
            {
                "data_path": "action_result.data.*.investigationId",
                "data_type": "numeric",
            },
            {
                "data_path": "action_result.data.*.investigationState",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.lastEventTime", "data_type": "string"},
            {"data_path": "action_result.data.*.lastUpdateTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.accountName",
                "data_type": "string",
                "example_values": ["Test"],
            },
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.domainName",
                "data_type": "string",
                "example_values": ["WINATPC2"],
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
            },
            {"data_path": "action_result.data.*.rbacGroupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.relatedUser.domainName",
                "data_type": "string",
                "contains": ["domain"],
            },
            {
                "data_path": "action_result.data.*.relatedUser.userName",
                "data_type": "string",
                "contains": ["user name"],
            },
            {"data_path": "action_result.data.*.resolvedTime", "data_type": "string"},
            {"data_path": "action_result.data.*.severity", "data_type": "string"},
            {"data_path": "action_result.data.*.status", "data_type": "string"},
            {
                "data_path": "action_result.data.*.threatFamilyName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.threatName", "data_type": "string"},
            {"data_path": "action_result.data.*.title", "data_type": "string"},
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Updated Alert"],
            }
        ],
    },
    "domain_prevalence": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#microsoft.windowsDefenderATP.api.InOrgDomainStats"
                ],
            },
            {
                "data_path": "action_result.data.*.host",
                "data_type": "string",
                "contains": ["domain"],
                "example_values": ["abc.com"],
                "column_name": "Host Name",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.orgFirstSeen",
                "data_type": "string",
                "column_name": "Organization First Seen",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.orgLastSeen",
                "data_type": "string",
                "column_name": "Organization Last Seen",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.orgPrevalence",
                "data_type": "string",
                "example_values": ["0"],
            },
            {
                "data_path": "action_result.data.*.organizationPrevalence",
                "data_type": "numeric",
                "example_values": [0],
                "column_name": "Organization Prevalence",
                "column_order": 1,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.organization_prevalence",
                "data_type": "numeric",
                "example_values": [0],
            }
        ],
    },
    "ip_prevalence": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#microsoft.windowsDefenderATP.api.InOrgIPStats"
                ],
            },
            {
                "data_path": "action_result.data.*.ipAddress",
                "data_type": "string",
                "contains": ["ip", "ipv6"],
                "example_values": [
                    "172.217.9.206",
                    "2001:0db8:0000:0000:0000:ff00:0042:8329",
                ],
                "column_name": "IP Address",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.orgFirstSeen",
                "data_type": "string",
                "example_values": ["2021-08-02T10:18:39.9233319Z"],
                "column_name": "Organization First Seen",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.orgLastSeen",
                "data_type": "string",
                "example_values": ["2021-08-02T10:18:39.9233319Z"],
                "column_name": "Organization Last Seen",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.orgPrevalence",
                "data_type": "string",
                "example_values": ["1"],
            },
            {
                "data_path": "action_result.data.*.organizationPrevalence",
                "data_type": "numeric",
                "example_values": [1],
                "column_name": "Organization Prevalence",
                "column_order": 1,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.organization_prevalence",
                "data_type": "numeric",
                "example_values": [1],
            }
        ],
    },
    "file_prevalence": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#microsoft.windowsDefenderATP.api.InOrgFileStats"
                ],
            },
            {
                "data_path": "action_result.data.*.globalFirstObserved",
                "data_type": "string",
                "example_values": ["2021-07-11T08:50:15.2316886Z"],
                "column_name": "Global First Observed",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.globalLastObserved",
                "data_type": "string",
                "example_values": ["2021-08-20T10:15:33.4741238Z"],
                "column_name": "Global Last Observed",
                "column_order": 6,
            },
            {
                "data_path": "action_result.data.*.globalPrevalence",
                "data_type": "string",
                "example_values": ["64356"],
            },
            {
                "data_path": "action_result.data.*.globallyPrevalence",
                "data_type": "numeric",
                "example_values": [64356],
                "column_name": "Global Prevalence",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.orgFirstSeen",
                "data_type": "string",
                "column_name": "Organization First Seen",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.orgLastSeen",
                "data_type": "string",
                "column_name": "Organization Last Seen",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.orgPrevalence",
                "data_type": "string",
                "example_values": ["0"],
            },
            {
                "data_path": "action_result.data.*.organizationPrevalence",
                "data_type": "numeric",
                "example_values": [0],
                "column_name": "Organization Prevalence",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
                "example_values": [
                    "954e0fd64a1242d0fa860b220198118268e35018"  # pragma: allowlist secret
                ],
                "column_name": "SHA1",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.topFileNames",
                "data_type": "string",
                "contains": ["file name"],
                "example_values": ["mssense.exe"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.organization_prevalence",
                "data_type": "numeric",
                "example_values": [0],
            }
        ],
    },
    "get_file_info": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#Files/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.determinationType",
                "data_type": "string",
                "example_values": ["Unknown"],
            },
            {
                "data_path": "action_result.data.*.determinationValue",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.fileProductName",
                "data_type": "string",
                "example_values": ["Windows Operating System"],
            },
            {"data_path": "action_result.data.*.filePublisher", "data_type": "string"},
            {"data_path": "action_result.data.*.fileType", "data_type": "string"},
            {
                "data_path": "action_result.data.*.globalFirstObserved",
                "data_type": "string",
                "example_values": ["2021-07-11T08:50:15.2316886Z"],
                "column_name": "Global First Observed",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.globalLastObserved",
                "data_type": "string",
                "example_values": ["2021-08-19T10:33:39.6552836Z"],
                "column_name": "Global Last Observed",
                "column_order": 6,
            },
            {
                "data_path": "action_result.data.*.globalPrevalence",
                "data_type": "numeric",
                "example_values": [64134],
                "column_name": "Global Prevalence",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.isPeFile",
                "data_type": "boolean",
                "example_values": [True],
            },
            {
                "data_path": "action_result.data.*.isValidCertificate",
                "data_type": "boolean",
                "example_values": [True],
            },
            {
                "data_path": "action_result.data.*.issuer",
                "data_type": "string",
                "example_values": ["Test Windows Production PCA 2011"],
                "column_name": "Issuer",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.md5",
                "data_type": "string",
                "contains": ["md5"],
                "example_values": [
                    "44adb27786eb24e5bbfd06b69e84d252"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
                "example_values": [
                    "954e0fd64a1242d0fa860b220198118268e35018"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.sha256",
                "data_type": "string",
                "contains": ["sha256"],
                "example_values": [
                    "1a563e59bfcdc9e7b4d8ac81c6b6579e2d215952f6dd98e0ab1ab026ac616896"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.signer",
                "data_type": "string",
                "example_values": ["Windows Publisher"],
            },
            {
                "data_path": "action_result.data.*.signerHash",
                "data_type": "string",
                "example_values": [
                    "4f95a05d113f1f31b481e92f8f0d2b9889545004"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.size",
                "data_type": "numeric",
                "example_values": [5395384],
                "column_name": "Size",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "example_values": ["success", "failure"],
                "column_name": "Status",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.file_hash",
                "data_type": "string",
                "contains": ["sha1", "sha256"],
                "example_values": [
                    "954e0fd64a1242d0fa860b220198118268e35018",  # pragma: allowlist secret
                    "1a563e59bfcdc9e7b4d8ac81c6b6579e2d215952f6dd98e0ab1ab026ac616896",  # pragma: allowlist secret
                ],
                "column_name": "File Hash",
                "column_order": 1,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.global_prevalence",
                "data_type": "numeric",
                "example_values": [64355],
            }
        ],
    },
    "get_file_related_devices": {
        "data": [
            {"data_path": "action_result.data.*.aadDeviceId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.agentVersion",
                "data_type": "string",
                "example_values": ["10.7740.19041.1110"],
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["testmachine4"],
            },
            {
                "data_path": "action_result.data.*.defenderAvStatus",
                "data_type": "string",
                "contains": ["domain"],
                "example_values": ["Updated"],
            },
            {
                "data_path": "action_result.data.*.deviceValue",
                "data_type": "string",
                "example_values": ["Normal"],
            },
            {
                "data_path": "action_result.data.*.exposureLevel",
                "data_type": "string",
                "example_values": ["Medium"],
            },
            {
                "data_path": "action_result.data.*.firstSeen",
                "data_type": "string",
                "example_values": ["2021-08-02T06:12:16.3736341Z"],
            },
            {
                "data_path": "action_result.data.*.healthStatus",
                "data_type": "string",
                "example_values": ["Inactive"],
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "803c416946e8738b7711903a28362adeae6e1aea"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.ipAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["10.1.1.4"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.macAddress",
                "data_type": "string",
                "example_values": [
                    "000D3A7B423C"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.operationalStatus",
                "data_type": "string",
                "example_values": ["Up"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.type",
                "data_type": "string",
                "example_values": ["Ethernet"],
            },
            {
                "data_path": "action_result.data.*.isAadJoined",
                "data_type": "boolean",
                "example_values": [False, True],
            },
            {
                "data_path": "action_result.data.*.lastExternalIpAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["137.116.83.101"],
            },
            {
                "data_path": "action_result.data.*.lastIpAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["10.1.1.4"],
            },
            {
                "data_path": "action_result.data.*.lastSeen",
                "data_type": "string",
                "example_values": ["2021-08-04T13:40:25.2473895Z"],
            },
            {"data_path": "action_result.data.*.managedBy", "data_type": "string"},
            {
                "data_path": "action_result.data.*.managedByStatus",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.onboardingStatus",
                "data_type": "string",
                "example_values": ["Onboarded"],
            },
            {
                "data_path": "action_result.data.*.osArchitecture",
                "data_type": "string",
                "example_values": ["64-bit"],
            },
            {
                "data_path": "action_result.data.*.osBuild",
                "data_type": "numeric",
                "example_values": [19042],
            },
            {
                "data_path": "action_result.data.*.osPlatform",
                "data_type": "string",
                "example_values": ["Windows10"],
            },
            {
                "data_path": "action_result.data.*.osProcessor",
                "data_type": "string",
                "example_values": ["x64"],
            },
            {"data_path": "action_result.data.*.osVersion", "data_type": "string"},
            {
                "data_path": "action_result.data.*.rbacGroupId",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.rbacGroupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.riskScore",
                "data_type": "string",
                "example_values": ["Medium"],
            },
            {
                "data_path": "action_result.data.*.version",
                "data_type": "string",
                "example_values": ["20H2"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.cloudProvider",
                "data_type": "string",
                "example_values": ["Azure"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.resourceId",
                "data_type": "string",
                "example_values": [
                    "/subscriptions/1b922e46-8595-4749-997a-1205e714cd91/resourceGroups/evaluation_3e5d447ba5d6470b9636a8709cd5b26a_4/providers/Microsoft.Compute/virtualMachines/TestMachine4"
                ],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.subscriptionId",
                "data_type": "string",
                "example_values": ["1b922e46-8595-4749-997a-1205e714cd91"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.vmId",
                "data_type": "string",
                "example_values": ["238443dc-56ce-487f-aeb6-261a2a00a38c"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_devices",
                "data_type": "numeric",
                "example_values": [1],
            }
        ],
    },
    "get_user_related_devices": {
        "data": [
            {"data_path": "action_result.data.*.aadDeviceId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.agentVersion",
                "data_type": "string",
                "example_values": ["10.7740.19041.1110"],
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "contains": ["domain"],
                "example_values": ["testmachine4"],
            },
            {
                "data_path": "action_result.data.*.defenderAvStatus",
                "data_type": "string",
                "example_values": ["Updated"],
            },
            {
                "data_path": "action_result.data.*.deviceValue",
                "data_type": "string",
                "example_values": ["Normal"],
            },
            {
                "data_path": "action_result.data.*.exposureLevel",
                "data_type": "string",
                "example_values": ["Medium"],
            },
            {
                "data_path": "action_result.data.*.firstSeen",
                "data_type": "string",
                "example_values": ["2021-08-02T06:12:16.3736341Z"],
            },
            {
                "data_path": "action_result.data.*.healthStatus",
                "data_type": "string",
                "example_values": ["Inactive"],
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "803c416946e8738b7711903a28362adeae6e1aea"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.ipAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["10.1.1.4"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.macAddress",
                "data_type": "string",
                "example_values": [
                    "000D3A7B423C"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.operationalStatus",
                "data_type": "string",
                "example_values": ["Up"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.type",
                "data_type": "string",
                "example_values": ["Ethernet"],
            },
            {
                "data_path": "action_result.data.*.isAadJoined",
                "data_type": "boolean",
                "example_values": [False],
            },
            {
                "data_path": "action_result.data.*.lastExternalIpAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["137.116.83.101"],
            },
            {
                "data_path": "action_result.data.*.lastIpAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["10.1.1.4"],
            },
            {
                "data_path": "action_result.data.*.lastSeen",
                "data_type": "string",
                "example_values": ["2021-08-04T13:40:25.2473895Z"],
            },
            {"data_path": "action_result.data.*.managedBy", "data_type": "string"},
            {
                "data_path": "action_result.data.*.managedByStatus",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.onboardingStatus",
                "data_type": "string",
                "example_values": ["Onboarded"],
            },
            {
                "data_path": "action_result.data.*.osArchitecture",
                "data_type": "string",
                "example_values": ["64-bit"],
            },
            {
                "data_path": "action_result.data.*.osBuild",
                "data_type": "numeric",
                "example_values": [19042],
            },
            {
                "data_path": "action_result.data.*.osPlatform",
                "data_type": "string",
                "example_values": ["Windows10"],
            },
            {
                "data_path": "action_result.data.*.osProcessor",
                "data_type": "string",
                "example_values": ["x64"],
            },
            {"data_path": "action_result.data.*.osVersion", "data_type": "string"},
            {
                "data_path": "action_result.data.*.rbacGroupId",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.rbacGroupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.riskScore",
                "data_type": "string",
                "example_values": ["Medium"],
            },
            {
                "data_path": "action_result.data.*.version",
                "data_type": "string",
                "example_values": ["20H2"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.cloudProvider",
                "data_type": "string",
                "example_values": ["Azure"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.resourceId",
                "data_type": "string",
                "example_values": [
                    "/subscriptions/1b922e46-8595-4749-997a-1205e714cd91/resourceGroups/evaluation_3e5d447ba5d6470b9636a8709cd5b26a_4/providers/Microsoft.Compute/virtualMachines/TestMachine4"
                ],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.subscriptionId",
                "data_type": "string",
                "example_values": ["1b922e46-8595-4749-997a-1205e714cd91"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.vmId",
                "data_type": "string",
                "example_values": ["238443dc-56ce-487f-aeb6-261a2a00a38c"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_devices",
                "data_type": "numeric",
                "example_values": [1],
            }
        ],
    },
    "get_installed_software": {
        "data": [
            {
                "data_path": "action_result.data.*.activeAlert",
                "data_type": "boolean",
                "example_values": [False],
                "column_name": "Active Alert",
                "column_order": 6,
            },
            {"data_path": "action_result.data.*.category", "data_type": "string"},
            {
                "data_path": "action_result.data.*.exposedMachines",
                "data_type": "numeric",
                "example_values": [0],
                "column_name": "Exposed Machines",
                "column_order": 7,
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "example_values": ["test-_-.net_framework"],
                "column_name": "Software ID",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.impactScore",
                "data_type": "numeric",
                "example_values": [0],
                "column_name": "Impact Score",
                "column_order": 9,
            },
            {
                "data_path": "action_result.data.*.installedMachines",
                "data_type": "numeric",
                "example_values": [5],
                "column_name": "Installed Machines",
                "column_order": 8,
            },
            {
                "data_path": "action_result.data.*.isNormalized",
                "data_type": "boolean",
                "example_values": [True, False],
            },
            {
                "data_path": "action_result.data.*.name",
                "data_type": "string",
                "example_values": [".net_framework"],
                "column_name": "Software Name",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.publicExploit",
                "data_type": "boolean",
                "example_values": [False],
                "column_name": "Public Exploit",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.vendor",
                "data_type": "string",
                "example_values": ["Test Vendor"],
                "column_name": "Vendor",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.weaknesses",
                "data_type": "numeric",
                "example_values": [0],
                "column_name": "Weaknesses",
                "column_order": 4,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_software",
                "data_type": "numeric",
                "example_values": [9],
            }
        ],
    },
    "restrict_app_execution": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.cancellationComment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationDateTimeUtc",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationRequestor",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["win10atp2"],
            },
            {
                "data_path": "action_result.data.*.creationDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T08:50:05.8076226Z"],
            },
            {"data_path": "action_result.data.*.error", "data_type": "string"},
            {
                "data_path": "action_result.data.*.errorHResult",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["6925706d-3a7e-4596-b2d7-321fca9cd965"],
                "column_name": "Event ID",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.lastUpdateDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T08:50:05.8076226Z"],
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "349838747f77ec74e43ab7ca70773a41f7bfb6f2"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.requestSource",
                "data_type": "string",
                "example_values": ["PublicApi"],
            },
            {
                "data_path": "action_result.data.*.requestor",
                "data_type": "string",
                "example_values": ["65265db5-a7ca-4199-a425-f37ad1dd6d31"],
            },
            {
                "data_path": "action_result.data.*.requestorComment",
                "data_type": "string",
                "example_values": ["Restrict code execution due to alert 1234"],
            },
            {"data_path": "action_result.data.*.scope", "data_type": "string"},
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "example_values": ["Succeeded"],
                "column_name": "Status",
                "column_order": 4,
            },
            {"data_path": "action_result.data.*.title", "data_type": "string"},
            {
                "data_path": "action_result.data.*.troubleshootInfo",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.type",
                "data_type": "string",
                "example_values": ["RestrictCodeExecution"],
                "column_name": "Event Type",
                "column_order": 3,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.event_id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["6925706d-3a7e-4596-b2d7-321fca9cd965"],
            },
            {
                "data_path": "action_result.summary.restrict_app_execution_status",
                "data_type": "string",
                "example_values": ["Succeeded"],
            },
            {
                "data_path": "action_result.summary.restriction_status",
                "data_type": "string",
                "example_values": ["Pending"],
            },
        ],
    },
    "list_indicators": {
        "data": [
            {
                "data_path": "action_result.data.*.action",
                "data_type": "string",
                "example_values": [
                    "Alert",
                    "Warn",
                    "Block",
                    "Audit",
                    "BlockAndRemediate",
                    "AlertAndBlock",
                    "Allowed",
                ],
                "column_name": "Action",
                "column_order": 2,
            },
            {"data_path": "action_result.data.*.additionalInfo", "data_type": "string"},
            {"data_path": "action_result.data.*.application", "data_type": "string"},
            {
                "data_path": "action_result.data.*.bypassDurationHours",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.category",
                "data_type": "numeric",
                "example_values": [1],
            },
            {
                "data_path": "action_result.data.*.certificateInfo.issuer",
                "data_type": "string",
                "example_values": [
                    "E=test@DS1234.testing.net, CN=localhost, OU=QA, O=System, L=ABC, "
                    "S=UT, C=US"
                ],
            },
            {
                "data_path": "action_result.data.*.certificateInfo.serial",
                "data_type": "string",
                "example_values": [
                    "123CE453421A81E2DB9A6A08C3440DBD06"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.certificateInfo.sha256",
                "data_type": "string",
                "example_values": [
                    "1234edd57a56d859cd9b18c3b20308917ea2fa5b2013f00d5c98d5a8a9be1234"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.certificateInfo.subject",
                "data_type": "string",
                "example_values": [
                    "E=test@DS1234.testing.net, CN=localhost, OU=QA, O=System, L=ABC, "
                    "S=UT, C=US"
                ],
            },
            {
                "data_path": "action_result.data.*.createdBy",
                "data_type": "string",
                "example_values": ["test@testdomain.onmicrosoft.com"],
            },
            {
                "data_path": "action_result.data.*.createdByDisplayName",
                "data_type": "string",
                "example_values": ["testuser@domain.onmicrosoft.com"],
                "column_name": "Created By",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.createdBySource",
                "data_type": "string",
                "example_values": ["Portal"],
            },
            {
                "data_path": "action_result.data.*.creationTimeDateTimeUtc",
                "data_type": "string",
                "example_values": ["2021-08-25T12:30:51.7279453Z"],
            },
            {
                "data_path": "action_result.data.*.description",
                "data_type": "string",
                "example_values": ["Test-ATP"],
            },
            {"data_path": "action_result.data.*.educateUrl", "data_type": "string"},
            {
                "data_path": "action_result.data.*.expirationTime",
                "data_type": "string",
                "example_values": ["2021-08-26T00:00:00Z"],
            },
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.generateAlert",
                "data_type": "boolean",
                "example_values": [False, True],
            },
            {
                "data_path": "action_result.data.*.historicalDetection",
                "data_type": "boolean",
                "example_values": [False, True],
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp indicator id"],
                "example_values": ["13"],
                "column_name": "Indicator ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.indicatorType",
                "data_type": "string",
                "example_values": [
                    "FileSha1",
                    "FileMd5",
                    "CertificateThumbprint",
                    "FileSha256",
                    "IpAddress",
                    "DomainName",
                    "Url",
                ],
                "column_name": "Indicator Type",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.indicatorValue",
                "data_type": "string",
                "contains": [
                    "defender atp indicator value",
                    "sha1",
                    "sha256",
                    "md5",
                    "domain",
                    "ip",
                    "ipv6",
                    "url",
                ],
                "example_values": [
                    "63b79504702c9c977e7165ad75d2e6989b2c5962"  # pragma: allowlist secret
                ],
                "column_name": "Indicator Value",
                "column_order": 6,
            },
            {
                "data_path": "action_result.data.*.lastUpdateTime",
                "data_type": "string",
                "example_values": ["2021-08-25T12:30:51.7457726Z"],
            },
            {"data_path": "action_result.data.*.lastUpdatedBy", "data_type": "string"},
            {"data_path": "action_result.data.*.lookBackPeriod", "data_type": "string"},
            {
                "data_path": "action_result.data.*.notificationBody",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.notificationId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.recommendedActions",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.severity",
                "data_type": "string",
                "example_values": ["Informational"],
                "column_name": "Severity",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.title",
                "data_type": "string",
                "example_values": ["Test"],
                "column_name": "Title",
                "column_order": 1,
            },
            {"data_path": "action_result.data.*.version", "data_type": "string"},
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_indicators",
                "data_type": "numeric",
                "example_values": [1],
            }
        ],
    },
    "collect_investigation_package": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp action id"],
                "column_name": "Action ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.type",
                "data_type": "string",
                "column_name": "Action Type",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.scope",
                "data_type": "string",
                "column_name": "Scope",
                "column_order": 2,
            },
            {"data_path": "action_result.data.*.requestor", "data_type": "string"},
            {
                "data_path": "action_result.data.*.requestorComment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "column_name": "Status",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "column_name": "Machine ID",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.creationDateTimeUtc",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.lastUpdateDateTimeUtc",
                "data_type": "string",
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Collected Investigation Package"],
            }
        ],
    },
    "get_investigation_uri": {
        "data": [
            {
                "data_path": "action_result.data.*.value",
                "data_type": "string",
                "column_name": "Investigation Package URI",
                "column_order": 0,
            }
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Investigation URI"],
            }
        ],
    },
    "get_device_details": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "column_name": "Device ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.firstSeen",
                "data_type": "string",
                "column_name": "First Seen",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.lastSeen",
                "data_type": "string",
                "column_name": "Last Seen",
                "column_order": 2,
            },
            {"data_path": "action_result.data.*.osPlatform", "data_type": "string"},
            {"data_path": "action_result.data.*.version", "data_type": "string"},
            {"data_path": "action_result.data.*.osProcessor", "data_type": "string"},
            {"data_path": "action_result.data.*.lastIpAddress", "data_type": "string"},
            {
                "data_path": "action_result.data.*.lastExternalIpAddress",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.osBuild", "data_type": "numeric"},
            {
                "data_path": "action_result.data.*.healthStatus",
                "data_type": "string",
                "column_name": "Health Status",
                "column_order": 3,
            },
            {"data_path": "action_result.data.*.rbacGroupId", "data_type": "numeric"},
            {"data_path": "action_result.data.*.rbacGroupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.riskScore",
                "data_type": "string",
                "column_name": "Risk Score",
                "column_order": 4,
            },
            {"data_path": "action_result.data.*.exposureLevel", "data_type": "string"},
            {"data_path": "action_result.data.*.isAadJoined", "data_type": "boolean"},
            {"data_path": "action_result.data.*.aadDeviceId", "data_type": "string"},
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Device Details"],
            }
        ],
    },
    "get_affected_devices": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "column_name": "Device ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "column_name": "Computer DNS Name",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.osPlatform",
                "data_type": "string",
                "column_name": "Operating System",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.rbacGroupName",
                "data_type": "string",
                "column_name": "RBAC Group Name",
                "column_order": 3,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Affected Devices"],
            },
            {
                "data_path": "action_result.summary.total_results",
                "data_type": "numeric",
            },
        ],
    },
    "get_indicator": {
        "data": [
            {
                "data_path": "action_result.data.*.action",
                "data_type": "string",
                "column_name": "Action",
                "column_order": 2,
            },
            {"data_path": "action_result.data.*.additionalInfo", "data_type": "string"},
            {"data_path": "action_result.data.*.application", "data_type": "string"},
            {
                "data_path": "action_result.data.*.bypassDurationHours",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.category", "data_type": "numeric"},
            {
                "data_path": "action_result.data.*.certificateInfo.issuer",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.certificateInfo.serial",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.certificateInfo.sha256",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.certificateInfo.subject",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.createdBy", "data_type": "string"},
            {
                "data_path": "action_result.data.*.createdByDisplayName",
                "data_type": "string",
                "column_name": "Created By",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.createdBySource",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.creationTimeDateTimeUtc",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.description", "data_type": "string"},
            {"data_path": "action_result.data.*.educateUrl", "data_type": "string"},
            {"data_path": "action_result.data.*.expirationTime", "data_type": "string"},
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {"data_path": "action_result.data.*.generateAlert", "data_type": "boolean"},
            {
                "data_path": "action_result.data.*.historicalDetection",
                "data_type": "boolean",
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp indicator id"],
                "column_name": "Indicator ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.indicatorType",
                "data_type": "string",
                "column_name": "Indicator Type",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.indicatorValue",
                "data_type": "string",
                "contains": [
                    "defender atp indicator value",
                    "sha1",
                    "sha256",
                    "md5",
                    "domain",
                    "ip",
                    "ipv6",
                    "url",
                ],
                "column_name": "Indicator Value",
                "column_order": 6,
            },
            {"data_path": "action_result.data.*.lastUpdateTime", "data_type": "string"},
            {"data_path": "action_result.data.*.lastUpdatedBy", "data_type": "string"},
            {"data_path": "action_result.data.*.lookBackPeriod", "data_type": "string"},
            {
                "data_path": "action_result.data.*.notificationBody",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.notificationId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.recommendedActions",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.severity",
                "data_type": "string",
                "column_name": "Severity",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.title",
                "data_type": "string",
                "column_name": "Title",
                "column_order": 1,
            },
            {"data_path": "action_result.data.*.version", "data_type": "string"},
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Indicator"],
            }
        ],
    },
    "submit_indicator": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#Indicators/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.action",
                "data_type": "string",
                "example_values": [
                    "Alert",
                    "Warn",
                    "Block",
                    "Audit",
                    "BlockAndRemediate",
                    "AlertAndBlock",
                    "Allowed",
                ],
                "column_name": "Action",
                "column_order": 2,
            },
            {"data_path": "action_result.data.*.additionalInfo", "data_type": "string"},
            {"data_path": "action_result.data.*.application", "data_type": "string"},
            {
                "data_path": "action_result.data.*.bypassDurationHours",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.category",
                "data_type": "numeric",
                "example_values": [1],
            },
            {
                "data_path": "action_result.data.*.createdBy",
                "data_type": "string",
                "example_values": ["65265db5-a7ca-4199-a425-f37ad1dd6d31"],
            },
            {
                "data_path": "action_result.data.*.createdByDisplayName",
                "data_type": "string",
                "example_values": ["WindowsDefenderATPSiemConnector"],
                "column_name": "Created By",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.createdBySource",
                "data_type": "string",
                "example_values": ["PublicApi"],
            },
            {
                "data_path": "action_result.data.*.creationTimeDateTimeUtc",
                "data_type": "string",
                "example_values": ["2021-08-27T12:50:54.882519Z"],
            },
            {
                "data_path": "action_result.data.*.description",
                "data_type": "string",
                "example_values": ["Test 1"],
            },
            {"data_path": "action_result.data.*.educateUrl", "data_type": "string"},
            {
                "data_path": "action_result.data.*.expirationTime",
                "data_type": "string",
                "example_values": ["2021-09-07T00:00:00Z"],
            },
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.generateAlert",
                "data_type": "boolean",
                "example_values": [False, True],
                "column_name": "Generate Alert",
                "column_order": 7,
            },
            {
                "data_path": "action_result.data.*.historicalDetection",
                "data_type": "boolean",
                "example_values": [False, True],
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp indicator id"],
                "example_values": ["17"],
                "column_name": "Indicator ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.indicatorType",
                "data_type": "string",
                "example_values": [
                    "FileSha1",
                    "FileMd5",
                    "CertificateThumbprint",
                    "FileSha256",
                    "IpAddress",
                    "DomainName",
                    "Url",
                ],
                "column_name": "Indicator Type",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.indicatorValue",
                "data_type": "string",
                "contains": [
                    "defender atp indicator value",
                    "ip",
                    "ipv6",
                    "sha1",
                    "sha256",
                    "md5",
                    "domain",
                    "url",
                ],
                "example_values": ["test.com"],
                "column_name": "Indicator Value",
                "column_order": 6,
            },
            {
                "data_path": "action_result.data.*.lastUpdateTime",
                "data_type": "string",
                "example_values": ["2021-08-27T12:55:42.0621261Z"],
            },
            {
                "data_path": "action_result.data.*.lastUpdatedBy",
                "data_type": "string",
                "example_values": ["65265db5-a7ca-4199-a425-f37ad1dd6d31"],
            },
            {"data_path": "action_result.data.*.lookBackPeriod", "data_type": "string"},
            {
                "data_path": "action_result.data.*.notificationBody",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.notificationId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.recommendedActions",
                "data_type": "string",
                "example_values": ["Test Actions"],
            },
            {
                "data_path": "action_result.data.*.severity",
                "data_type": "string",
                "example_values": ["Low"],
                "column_name": "Severity",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.title",
                "data_type": "string",
                "example_values": ["Test 1"],
                "column_name": "Title",
                "column_order": 1,
            },
            {"data_path": "action_result.data.*.version", "data_type": "string"},
        ],
        "summary": [
            {
                "data_path": "action_result.summary.indicator_id",
                "data_type": "string",
                "contains": ["defender atp indicator id"],
                "example_values": ["17"],
            }
        ],
    },
    "update_indicator": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp indicator id"],
                "column_name": "Indicator ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.indicator",
                "data_type": "string",
                "column_name": "Indicator Value",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.isFailed",
                "data_type": "boolean",
                "column_name": "Failed",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.failureReason",
                "data_type": "string",
                "column_name": "Failure Reason",
                "column_order": 3,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Updated Indicator"],
            }
        ],
    },
    "update_indicator_batch": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp indicator id"],
                "column_name": "Indicator ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.indicator",
                "data_type": "string",
                "column_name": "Indicator Value",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.isFailed",
                "data_type": "boolean",
                "column_name": "Failed",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.failureReason",
                "data_type": "string",
                "column_name": "Failure Reason",
                "column_order": 3,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Updated batch of indicators"],
            },
            {
                "data_path": "action_result.summary.total_results",
                "data_type": "numeric",
                "example_values": [5],
            },
        ],
    },
    "get_file_alerts": {
        "data": [
            {"data_path": "action_result.data.*.aadTenantId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.alertCreationTime",
                "data_type": "string",
                "column_name": "Alert Creation Time",
                "column_order": 2,
            },
            {"data_path": "action_result.data.*.assignedTo", "data_type": "string"},
            {
                "data_path": "action_result.data.*.category",
                "data_type": "string",
                "column_name": "Category",
                "column_order": 3,
            },
            {"data_path": "action_result.data.*.classification", "data_type": "string"},
            {
                "data_path": "action_result.data.*.comments.*.comment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdBy",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.description", "data_type": "string"},
            {
                "data_path": "action_result.data.*.detectionSource",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.detectorId", "data_type": "string"},
            {"data_path": "action_result.data.*.determination", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.aadUserId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.detectionStatus",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.domainName",
                "data_type": "string",
                "contains": ["domain"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.entityType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.evidenceCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.fileName",
                "data_type": "string",
                "contains": ["file name"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.filePath",
                "data_type": "string",
                "contains": ["file path"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.ipAddress",
                "data_type": "string",
                "contains": ["ip"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFileName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFilePath",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCommandLine",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryHive",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryKey",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValue",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha256",
                "data_type": "string",
                "contains": ["sha256"],
            },
            {"data_path": "action_result.data.*.evidence.*.url", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.userPrincipalName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.userSid",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.firstEventTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp alert id"],
                "column_name": "Alert ID",
                "column_order": 0,
            },
            {"data_path": "action_result.data.*.incidentId", "data_type": "numeric"},
            {
                "data_path": "action_result.data.*.investigationId",
                "data_type": "numeric",
            },
            {
                "data_path": "action_result.data.*.investigationState",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.lastEventTime", "data_type": "string"},
            {"data_path": "action_result.data.*.lastUpdateTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.domainName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
            },
            {"data_path": "action_result.data.*.rbacGroupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.relatedUser.domainName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.relatedUser.userName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.resolvedTime", "data_type": "string"},
            {"data_path": "action_result.data.*.severity", "data_type": "string"},
            {"data_path": "action_result.data.*.status", "data_type": "string"},
            {
                "data_path": "action_result.data.*.threatFamilyName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.threatName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.title",
                "data_type": "string",
                "column_name": "Title",
                "column_order": 1,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Alerts for File"],
            },
            {
                "data_path": "action_result.summary.total_results",
                "data_type": "numeric",
                "example_values": [5],
            },
        ],
    },
    "get_device_alerts": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp alert id"],
                "column_name": "Alert ID",
                "column_order": 0,
            },
            {"data_path": "action_result.data.*.aadTenantId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.alertCreationTime",
                "data_type": "string",
                "column_name": "Alert Creation Time",
                "column_order": 2,
            },
            {"data_path": "action_result.data.*.assignedTo", "data_type": "string"},
            {
                "data_path": "action_result.data.*.category",
                "data_type": "string",
                "column_name": "Category",
                "column_order": 3,
            },
            {"data_path": "action_result.data.*.classification", "data_type": "string"},
            {
                "data_path": "action_result.data.*.comments.*.comment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdBy",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.description", "data_type": "string"},
            {
                "data_path": "action_result.data.*.detectionSource",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.detectorId", "data_type": "string"},
            {"data_path": "action_result.data.*.determination", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.aadUserId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.detectionStatus",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.domainName",
                "data_type": "string",
                "contains": ["domain"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.entityType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.evidenceCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.fileName",
                "data_type": "string",
                "contains": ["file name"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.filePath",
                "data_type": "string",
                "contains": ["file path"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.ipAddress",
                "data_type": "string",
                "contains": ["ip"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFileName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFilePath",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCommandLine",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryHive",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryKey",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValue",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha256",
                "data_type": "string",
                "contains": ["sha256"],
            },
            {"data_path": "action_result.data.*.evidence.*.url", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.userPrincipalName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.userSid",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.firstEventTime", "data_type": "string"},
            {"data_path": "action_result.data.*.incidentId", "data_type": "numeric"},
            {
                "data_path": "action_result.data.*.investigationId",
                "data_type": "numeric",
            },
            {
                "data_path": "action_result.data.*.investigationState",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.lastEventTime", "data_type": "string"},
            {"data_path": "action_result.data.*.lastUpdateTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.domainName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
            },
            {"data_path": "action_result.data.*.rbacGroupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.relatedUser.domainName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.relatedUser.userName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.resolvedTime", "data_type": "string"},
            {"data_path": "action_result.data.*.severity", "data_type": "string"},
            {"data_path": "action_result.data.*.status", "data_type": "string"},
            {
                "data_path": "action_result.data.*.threatFamilyName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.threatName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.title",
                "data_type": "string",
                "column_name": "Title",
                "column_order": 1,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Alerts for Device"],
            },
            {
                "data_path": "action_result.summary.total_results",
                "data_type": "numeric",
                "example_values": [10],
            },
        ],
    },
    "get_user_alerts": {
        "data": [
            {"data_path": "action_result.data.*.aadTenantId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.alertCreationTime",
                "data_type": "string",
                "column_name": "Alert Creation Time",
                "column_order": 2,
            },
            {"data_path": "action_result.data.*.assignedTo", "data_type": "string"},
            {
                "data_path": "action_result.data.*.category",
                "data_type": "string",
                "column_name": "Category",
                "column_order": 3,
            },
            {"data_path": "action_result.data.*.classification", "data_type": "string"},
            {
                "data_path": "action_result.data.*.comments.*.comment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdBy",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.description", "data_type": "string"},
            {
                "data_path": "action_result.data.*.detectionSource",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.detectorId", "data_type": "string"},
            {"data_path": "action_result.data.*.determination", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.aadUserId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.detectionStatus",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.domainName",
                "data_type": "string",
                "contains": ["domain"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.entityType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.evidenceCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.fileName",
                "data_type": "string",
                "contains": ["file name"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.filePath",
                "data_type": "string",
                "contains": ["file path"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.ipAddress",
                "data_type": "string",
                "contains": ["ip"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFileName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFilePath",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCommandLine",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryHive",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryKey",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValue",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha256",
                "data_type": "string",
                "contains": ["sha256"],
            },
            {"data_path": "action_result.data.*.evidence.*.url", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.userPrincipalName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.userSid",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.firstEventTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp alert id"],
                "column_name": "Alert ID",
                "column_order": 0,
            },
            {"data_path": "action_result.data.*.incidentId", "data_type": "numeric"},
            {
                "data_path": "action_result.data.*.investigationId",
                "data_type": "numeric",
            },
            {
                "data_path": "action_result.data.*.investigationState",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.lastEventTime", "data_type": "string"},
            {"data_path": "action_result.data.*.lastUpdateTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.domainName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
            },
            {"data_path": "action_result.data.*.rbacGroupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.relatedUser.domainName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.relatedUser.userName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.resolvedTime", "data_type": "string"},
            {"data_path": "action_result.data.*.severity", "data_type": "string"},
            {"data_path": "action_result.data.*.status", "data_type": "string"},
            {
                "data_path": "action_result.data.*.threatFamilyName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.threatName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.title",
                "data_type": "string",
                "column_name": "Title",
                "column_order": 1,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Alerts for User"],
            },
            {
                "data_path": "action_result.summary.total_results",
                "data_type": "numeric",
                "example_values": [5],
            },
        ],
    },
    "get_domain_alerts": {
        "data": [
            {"data_path": "action_result.data.*.aadTenantId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.alertCreationTime",
                "data_type": "string",
                "column_name": "Alert Creation Time",
                "column_order": 2,
            },
            {"data_path": "action_result.data.*.assignedTo", "data_type": "string"},
            {
                "data_path": "action_result.data.*.category",
                "data_type": "string",
                "column_name": "Category",
                "column_order": 3,
            },
            {"data_path": "action_result.data.*.classification", "data_type": "string"},
            {
                "data_path": "action_result.data.*.comments.*.comment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdBy",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.comments.*.createdTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.description", "data_type": "string"},
            {
                "data_path": "action_result.data.*.detectionSource",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.detectorId", "data_type": "string"},
            {"data_path": "action_result.data.*.determination", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.aadUserId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.detectionStatus",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.domainName",
                "data_type": "string",
                "contains": ["domain"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.entityType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.evidenceCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.fileName",
                "data_type": "string",
                "contains": ["file name"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.filePath",
                "data_type": "string",
                "contains": ["file path"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.ipAddress",
                "data_type": "string",
                "contains": ["ip"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFileName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessFilePath",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.parentProcessId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCommandLine",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processCreationTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.processId",
                "data_type": "string",
                "contains": ["pid"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryHive",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryKey",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValue",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.registryValueType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha1",
                "data_type": "string",
                "contains": ["sha1"],
            },
            {
                "data_path": "action_result.data.*.evidence.*.sha256",
                "data_type": "string",
                "contains": ["sha256"],
            },
            {"data_path": "action_result.data.*.evidence.*.url", "data_type": "string"},
            {
                "data_path": "action_result.data.*.evidence.*.userPrincipalName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.evidence.*.userSid",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.firstEventTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp alert id"],
                "column_name": "Alert ID",
                "column_order": 0,
            },
            {"data_path": "action_result.data.*.incidentId", "data_type": "numeric"},
            {
                "data_path": "action_result.data.*.investigationId",
                "data_type": "numeric",
            },
            {
                "data_path": "action_result.data.*.investigationState",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.lastEventTime", "data_type": "string"},
            {"data_path": "action_result.data.*.lastUpdateTime", "data_type": "string"},
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.accountName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.loggedOnUsers.*.domainName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
            },
            {"data_path": "action_result.data.*.rbacGroupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.relatedUser.domainName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.relatedUser.userName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.resolvedTime", "data_type": "string"},
            {"data_path": "action_result.data.*.severity", "data_type": "string"},
            {"data_path": "action_result.data.*.status", "data_type": "string"},
            {
                "data_path": "action_result.data.*.threatFamilyName",
                "data_type": "string",
            },
            {"data_path": "action_result.data.*.threatName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.title",
                "data_type": "string",
                "column_name": "Title",
                "column_order": 1,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Retrieved Alerts for Domain"],
            },
            {
                "data_path": "action_result.summary.total_results",
                "data_type": "numeric",
                "example_values": [5],
            },
        ],
    },
    "delete_indicator": {"data": [], "summary": []},
    "run_query": {
        "data": [
            {
                "data_path": "action_result.data.*.ActionType",
                "data_type": "string",
                "example_values": ["RegistryKeyDeleted"],
            },
            {
                "data_path": "action_result.data.*.AntivirusEnabled",
                "data_type": "string",
                "example_values": ["BAD"],
            },
            {
                "data_path": "action_result.data.*.AntivirusReporting",
                "data_type": "string",
                "example_values": ["N/A"],
            },
            {
                "data_path": "action_result.data.*.AntivirusSignatureVersion",
                "data_type": "string",
                "example_values": ["N/A"],
            },
            {
                "data_path": "action_result.data.*.AppGuardContainerId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.BehaviorMonitoring",
                "data_type": "string",
                "example_values": ["GOOD"],
            },
            {
                "data_path": "action_result.data.*.CloudProtection",
                "data_type": "string",
                "example_values": ["BAD"],
            },
            {
                "data_path": "action_result.data.*.DeviceId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "803c416946e8738b7711903a28362adeae6e1aea"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.DeviceName",
                "data_type": "string",
                "example_values": ["testserver9"],
            },
            {
                "data_path": "action_result.data.*.DomainName",
                "data_type": "string",
                "contains": ["domain"],
                "example_values": ["TestServer9"],
            },
            {
                "data_path": "action_result.data.*.DurationAtLeast",
                "data_type": "string",
                "example_values": ["00.12:00:36"],
            },
            {
                "data_path": "action_result.data.*.FileName",
                "data_type": "string",
                "contains": ["file name"],
                "example_values": ["csc.exe"],
            },
            {
                "data_path": "action_result.data.*.ImpairedCommunications",
                "data_type": "string",
                "example_values": ["BAD"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessAccountDomain",
                "data_type": "string",
                "example_values": ["nt authority"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessAccountName",
                "data_type": "string",
                "example_values": ["system"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessAccountObjectId",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessAccountSid",
                "data_type": "string",
                "example_values": ["S-1-5-18"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessAccountUpn",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessCommandLine",
                "data_type": "string",
                "example_values": ["svchost.exe -k netsvcs -p -s wlidsvc"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessCreationTime",
                "data_type": "string",
                "example_values": ["2022-09-13T12:18:40.7867576Z"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessFileName",
                "data_type": "string",
                "contains": ["file name"],
                "example_values": ["powershell.exe"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessFileSize",
                "data_type": "numeric",
                "example_values": [59952],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessFolderPath",
                "data_type": "string",
                "example_values": ["c:\\windows\\system32\\test.exe"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessId",
                "data_type": "numeric",
                "example_values": [7656],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessIntegrityLevel",
                "data_type": "string",
                "example_values": ["System"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessMD5",
                "data_type": "string",
                "example_values": [
                    "cd10cb894be1234fca0bf0e2b0c27c16"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessParentCreationTime",
                "data_type": "string",
                "example_values": ["2022-07-15T08:34:44.3266266Z"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessParentFileName",
                "data_type": "string",
                "example_values": ["services.exe"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessParentId",
                "data_type": "numeric",
                "example_values": [756],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessSHA1",
                "data_type": "string",
                "example_values": [
                    "1f912d4bec338ef10b7c9f12346286f8acc4eb97"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessSHA256",
                "data_type": "string",
                "example_values": [
                    "f3feb95e7bcfb0766a694d93fca29eda7e2ca977c2395b4be75242814eb6d881"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessTokenElevation",
                "data_type": "string",
                "example_values": ["TokenElevationTypeDefault"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessVersionInfoCompanyName",
                "data_type": "string",
                "example_values": ["Microsoft Corporation"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessVersionInfoFileDescription",
                "data_type": "string",
                "example_values": ["Host Process for Windows Services"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessVersionInfoInternalFileName",
                "data_type": "string",
                "example_values": ["svchost.exe"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessVersionInfoOriginalFileName",
                "data_type": "string",
                "example_values": ["svchost.exe"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessVersionInfoProductName",
                "data_type": "string",
                "example_values": ["Microsoft® Windows® Operating System"],
            },
            {
                "data_path": "action_result.data.*.InitiatingProcessVersionInfoProductVersion",
                "data_type": "string",
                "example_values": ["10.0.19041.1566"],
            },
            {
                "data_path": "action_result.data.*.LastTimestamp",
                "data_type": "string",
                "example_values": ["2021-09-15T22:53:50.2952649Z"],
            },
            {
                "data_path": "action_result.data.*.PUAProtection",
                "data_type": "string",
                "example_values": ["N/A"],
            },
            {
                "data_path": "action_result.data.*.PreviousRegistryKey",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.PreviousRegistryValueData",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.PreviousRegistryValueName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.RealtimeProtection",
                "data_type": "string",
                "example_values": ["N/A"],
            },
            {"data_path": "action_result.data.*.RegistryKey", "data_type": "string"},
            {
                "data_path": "action_result.data.*.RegistryValueData",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.RegistryValueName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.RegistryValueType",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.ReportId",
                "data_type": "numeric",
                "example_values": [641555],
            },
            {
                "data_path": "action_result.data.*.SensorDataCollection",
                "data_type": "string",
                "example_values": ["BAD"],
            },
            {
                "data_path": "action_result.data.*.SensorEnabled",
                "data_type": "string",
                "example_values": ["BAD"],
            },
            {
                "data_path": "action_result.data.*.TamperProtection",
                "data_type": "string",
                "example_values": ["N/A"],
            },
            {
                "data_path": "action_result.data.*.Timestamp",
                "data_type": "string",
                "example_values": ["2021-09-15T10:53:13.5858707Z"],
            },
            {
                "data_path": "action_result.data.*.UserName",
                "data_type": "string",
                "contains": ["user name"],
                "example_values": ["administrator1"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_results",
                "data_type": "numeric",
                "example_values": [7],
            }
        ],
    },
    "get_domain_related_devices": {
        "data": [
            {"data_path": "action_result.data.*.aadDeviceId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.agentVersion",
                "data_type": "string",
                "example_values": ["10.7740.19041.1110"],
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["testmachine4"],
            },
            {
                "data_path": "action_result.data.*.defenderAvStatus",
                "data_type": "string",
                "example_values": ["Updated"],
            },
            {
                "data_path": "action_result.data.*.deviceValue",
                "data_type": "string",
                "example_values": ["Normal"],
            },
            {
                "data_path": "action_result.data.*.exposureLevel",
                "data_type": "string",
                "example_values": ["Medium"],
            },
            {
                "data_path": "action_result.data.*.firstSeen",
                "data_type": "string",
                "example_values": ["2021-08-02T06:12:16.3736341Z"],
            },
            {
                "data_path": "action_result.data.*.healthStatus",
                "data_type": "string",
                "example_values": ["Inactive"],
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "803c416946e8738b7711903a28362adeae6e1aea"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.ipAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["10.1.1.4"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.macAddress",
                "data_type": "string",
                "example_values": ["000X3X7X423X"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.operationalStatus",
                "data_type": "string",
                "example_values": ["Up"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.type",
                "data_type": "string",
                "example_values": ["Ethernet"],
            },
            {
                "data_path": "action_result.data.*.isAadJoined",
                "data_type": "boolean",
                "example_values": [False, True],
            },
            {
                "data_path": "action_result.data.*.lastExternalIpAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["137.116.83.101"],
            },
            {
                "data_path": "action_result.data.*.lastIpAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["10.1.1.4"],
            },
            {
                "data_path": "action_result.data.*.lastSeen",
                "data_type": "string",
                "example_values": ["2021-08-04T13:40:25.2473895Z"],
            },
            {
                "data_path": "action_result.data.*.managedBy",
                "data_type": "string",
                "example_values": ["Unknown"],
            },
            {
                "data_path": "action_result.data.*.managedByStatus",
                "data_type": "string",
                "example_values": ["Unknown"],
            },
            {
                "data_path": "action_result.data.*.onboardingStatus",
                "data_type": "string",
                "example_values": ["Onboarded"],
            },
            {
                "data_path": "action_result.data.*.osArchitecture",
                "data_type": "string",
                "example_values": ["64-bit"],
            },
            {
                "data_path": "action_result.data.*.osBuild",
                "data_type": "numeric",
                "example_values": [19042],
            },
            {
                "data_path": "action_result.data.*.osPlatform",
                "data_type": "string",
                "example_values": ["Windows10"],
            },
            {
                "data_path": "action_result.data.*.osProcessor",
                "data_type": "string",
                "example_values": ["x64"],
            },
            {"data_path": "action_result.data.*.osVersion", "data_type": "string"},
            {
                "data_path": "action_result.data.*.rbacGroupId",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.rbacGroupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.riskScore",
                "data_type": "string",
                "example_values": ["Medium"],
            },
            {
                "data_path": "action_result.data.*.version",
                "data_type": "string",
                "example_values": ["20H2"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.cloudProvider",
                "data_type": "string",
                "example_values": ["TestCloudProvider"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.resourceId",
                "data_type": "string",
                "example_values": [
                    "/subscriptions/1b922e46-8595-4749-997a-1205e714cd91/resourceGroups/evaluation_3e5d447ba5d6470b9636a8709cd5b26a_4/providers/Test.Compute/virtualMachines/TestMachine4"
                ],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.subscriptionId",
                "data_type": "string",
                "example_values": ["1b922e46-8595-4749-997a-1205e714cd91"],
            },
            {
                "data_path": "action_result.data.*.vmMetadata.vmId",
                "data_type": "string",
                "example_values": ["238443dc-56ce-487f-aeb6-261a2a00a38c"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_devices",
                "data_type": "numeric",
                "example_values": [1],
            }
        ],
    },
    "update_device_tag": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#Machines/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#Machines/$entity"
                ],
            },
            {"data_path": "action_result.data.*.aadDeviceId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.agentVersion",
                "data_type": "string",
                "example_values": ["10.5850.17763.404"],
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "contains": ["domain"],
                "example_values": ["desktop-ph2a1ro"],
            },
            {
                "data_path": "action_result.data.*.defenderAvStatus",
                "data_type": "string",
                "example_values": ["NotSupported"],
            },
            {
                "data_path": "action_result.data.*.defenderAvStatus",
                "data_type": "string",
                "example_values": ["NotSupported"],
            },
            {
                "data_path": "action_result.data.*.deviceValue",
                "data_type": "string",
                "example_values": ["Normal"],
            },
            {
                "data_path": "action_result.data.*.deviceValue",
                "data_type": "string",
                "example_values": ["Normal"],
            },
            {
                "data_path": "action_result.data.*.exposureLevel",
                "data_type": "string",
                "example_values": ["Medium"],
            },
            {
                "data_path": "action_result.data.*.firstSeen",
                "data_type": "string",
                "example_values": ["2019-04-16T00:27:12.2677222Z"],
            },
            {"data_path": "action_result.data.*.groupName", "data_type": "string"},
            {
                "data_path": "action_result.data.*.healthStatus",
                "data_type": "string",
                "example_values": ["Active"],
                "column_name": "Health Status",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "ae2e5bda4bb22ec9c321680079d03e5e4cdff400"  # pragma: allowlist secret
                ],
                "column_name": "Device ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.ipAddress",
                "data_type": "string",
                "example_values": ["10.0.2.15"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.ipAddress",
                "data_type": "string",
                "example_values": ["10.0.2.15"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.macAddress",
                "data_type": "string",
                "example_values": [
                    "002248242A86"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.macAddress",
                "data_type": "string",
                "example_values": [
                    "001238242A86"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.operationalStatus",
                "data_type": "string",
                "example_values": ["Up"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.operationalStatus",
                "data_type": "string",
                "example_values": ["Up"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.type",
                "data_type": "string",
                "example_values": ["Ethernet"],
            },
            {
                "data_path": "action_result.data.*.ipAddresses.*.type",
                "data_type": "string",
                "example_values": ["Ethernet"],
            },
            {
                "data_path": "action_result.data.*.isAadJoined",
                "data_type": "boolean",
                "example_values": [True, False],
            },
            {
                "data_path": "action_result.data.*.lastExternalIpAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["204.107.141.240"],
            },
            {
                "data_path": "action_result.data.*.lastIpAddress",
                "data_type": "string",
                "contains": ["ip"],
                "example_values": ["10.1.66.140"],
            },
            {
                "data_path": "action_result.data.*.lastSeen",
                "data_type": "string",
                "example_values": ["2019-05-03T05:23:45.9643247Z"],
            },
            {
                "data_path": "action_result.data.*.machineTags",
                "data_type": "string",
                "example_values": ["Test Tag -21"],
                "column_name": "Tag(s)",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.managedBy",
                "data_type": "string",
                "example_values": ["Unknown"],
            },
            {"data_path": "action_result.data.*.managedBy", "data_type": "string"},
            {
                "data_path": "action_result.data.*.managedByStatus",
                "data_type": "string",
                "example_values": ["Unknown"],
            },
            {
                "data_path": "action_result.data.*.managedByStatus",
                "data_type": "string",
                "example_values": ["Unknown"],
            },
            {
                "data_path": "action_result.data.*.onboardingStatus",
                "data_type": "string",
                "example_values": ["Onboarded"],
            },
            {
                "data_path": "action_result.data.*.onboardingStatus",
                "data_type": "string",
                "example_values": ["Onboarded"],
            },
            {
                "data_path": "action_result.data.*.osArchitecture",
                "data_type": "string",
                "example_values": ["64-bit"],
            },
            {
                "data_path": "action_result.data.*.osArchitecture",
                "data_type": "string",
                "example_values": ["64-bit"],
            },
            {
                "data_path": "action_result.data.*.osBuild",
                "data_type": "numeric",
                "example_values": [17763],
            },
            {
                "data_path": "action_result.data.*.osPlatform",
                "data_type": "string",
                "example_values": ["Windows10"],
                "column_name": "OS",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.osProcessor",
                "data_type": "string",
                "example_values": ["x64"],
            },
            {"data_path": "action_result.data.*.osVersion", "data_type": "string"},
            {
                "data_path": "action_result.data.*.rbacGroupId",
                "data_type": "numeric",
                "example_values": [0],
            },
            {
                "data_path": "action_result.data.*.rbacGroupName",
                "data_type": "string",
                "example_values": ["GROUP1"],
            },
            {
                "data_path": "action_result.data.*.riskScore",
                "data_type": "string",
                "example_values": ["None"],
            },
            {
                "data_path": "action_result.data.*.systemProductName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.version",
                "data_type": "string",
                "example_values": ["1809"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.operation",
                "data_type": "string",
                "example_values": ["Add"],
            },
            {
                "data_path": "action_result.summary.operation",
                "data_type": "string",
                "example_values": ["Add"],
            },
            {
                "data_path": "action_result.summary.tag",
                "data_type": "string",
                "example_values": ["test-new-ac"],
            },
            {
                "data_path": "action_result.summary.tag",
                "data_type": "string",
                "example_values": ["test-tag"],
            },
        ],
    },
    "get_discovered_vulnerabilities": {
        "data": [
            {"data_path": "action_result.data.*.@odata.type", "data_type": "string"},
            {
                "data_path": "action_result.data.*.@odata.type",
                "data_type": "string",
                "example_values": [
                    "#microsoft.windowsDefenderATP.api.PublicVulnerabilityDto"
                ],
            },
            {
                "data_path": "action_result.data.*.cvssV3",
                "data_type": "numeric",
                "example_values": [8.8],
                "column_name": "CvssV3",
                "column_order": 5,
            },
            {
                "data_path": "action_result.data.*.description",
                "data_type": "string",
                "example_values": [
                    "Windows User Profile Service Elevation of Privilege Vulnerability"
                ],
                "column_name": "Description",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.exploitInKit",
                "data_type": "numeric",
                "example_values": [False],
            },
            {
                "data_path": "action_result.data.*.exploitTypes",
                "data_type": "string",
                "example_values": ["Local"],
            },
            {
                "data_path": "action_result.data.*.exploitUris",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36934"
                ],
            },
            {
                "data_path": "action_result.data.*.exploitVerified",
                "data_type": "numeric",
                "example_values": [False],
            },
            {
                "data_path": "action_result.data.*.exposedMachines",
                "data_type": "numeric",
                "example_values": [1],
                "column_name": "Exposed Machines",
                "column_order": 6,
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "example_values": ["CVE-2021-30600"],
                "column_name": "Vulnerability ID",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.name",
                "data_type": "string",
                "example_values": ["CVE-2021-30600"],
                "column_name": "Vulnerability Name",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.publicExploit",
                "data_type": "numeric",
                "example_values": [False],
            },
            {
                "data_path": "action_result.data.*.publishedOn",
                "data_type": "string",
                "example_values": ["2021-08-16T00:00:00Z"],
            },
            {
                "data_path": "action_result.data.*.severity",
                "data_type": "string",
                "example_values": ["High"],
                "column_name": "Severity",
                "column_order": 4,
            },
            {
                "data_path": "action_result.data.*.updatedOn",
                "data_type": "string",
                "example_values": ["2021-08-23T00:00:00Z"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_vulnerabilities",
                "data_type": "numeric",
                "example_values": [7],
            }
        ],
    },
    "remove_app_restriction": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.cancellationComment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationDateTimeUtc",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationRequestor",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["win10atp2"],
            },
            {
                "data_path": "action_result.data.*.creationDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T08:50:05.8076226Z"],
            },
            {"data_path": "action_result.data.*.error", "data_type": "string"},
            {
                "data_path": "action_result.data.*.errorHResult",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["6925706d-3a7e-4596-b2d7-321fca9cd965"],
                "column_name": "Event ID",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.lastUpdateDateTimeUtc",
                "data_type": "string",
                "example_values": ["2019-05-03T08:50:05.8076226Z"],
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "349838747f77ec74e43ab7ca70773a41f7bfb6f2"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.requestSource",
                "data_type": "string",
                "example_values": ["PublicApi"],
            },
            {
                "data_path": "action_result.data.*.requestor",
                "data_type": "string",
                "example_values": ["65265db5-a7ca-4199-a425-f37ad1dd6d31"],
            },
            {
                "data_path": "action_result.data.*.requestorComment",
                "data_type": "string",
                "example_values": [
                    "Unrestrict code execution since machine was cleaned and validated"
                ],
            },
            {"data_path": "action_result.data.*.scope", "data_type": "string"},
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "example_values": ["Succeeded"],
                "column_name": "Status",
                "column_order": 4,
            },
            {"data_path": "action_result.data.*.title", "data_type": "string"},
            {
                "data_path": "action_result.data.*.troubleshootInfo",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.type",
                "data_type": "string",
                "example_values": ["UnrestrictCodeExecution"],
                "column_name": "Event Type",
                "column_order": 3,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.event_id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["6925706d-3a7e-4596-b2d7-321fca9cd965"],
            },
            {
                "data_path": "action_result.summary.remove_app_restriction_status",
                "data_type": "string",
                "example_values": ["Pending"],
            },
            {
                "data_path": "action_result.summary.restriction_status",
                "data_type": "string",
                "example_values": ["Pending"],
            },
        ],
    },
    "get_exposure_score": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#ExposureScore/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.rbacGroupId",
                "data_type": "string",
                "column_name": "RBAC Group ID",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.rbacGroupName",
                "data_type": "string",
                "column_name": "RBAC Group Name",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.score",
                "data_type": "numeric",
                "example_values": [46.23333333333333],
                "column_name": "Exposure Score",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.time",
                "data_type": "string",
                "example_values": ["2021-08-31T10:41:12.6341624Z"],
                "column_name": "Time",
                "column_order": 1,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.exposure_score",
                "data_type": "numeric",
                "example_values": [46.23333333333333],
            }
        ],
    },
    "get_secure_score": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#ConfigurationScore/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.rbacGroupId",
                "data_type": "string",
                "column_name": "RBAC Group ID",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.rbacGroupName",
                "data_type": "string",
                "column_name": "RBAC Group Name",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.score",
                "data_type": "numeric",
                "example_values": [350],
                "column_name": "Secure Score",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.time",
                "data_type": "string",
                "example_values": ["2021-08-31T10:55:48.6805335Z"],
                "column_name": "Time",
                "column_order": 1,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.secure_score",
                "data_type": "numeric",
                "example_values": [350],
            }
        ],
    },
    "get_file_live_response": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.cancellationComment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationDateTimeUtc",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationRequestor",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.commands.*.command.params.*.key",
                "data_type": "string",
                "example_values": ["Path"],
            },
            {
                "data_path": "action_result.data.*.commands.*.command.params.*.value",
                "data_type": "string",
                "contains": ["file path"],
                "example_values": ["C:\\Users\\administrator1\\Desktop\\test\\one.txt"],
            },
            {
                "data_path": "action_result.data.*.commands.*.command.type",
                "data_type": "string",
                "example_values": ["GetFile"],
            },
            {
                "data_path": "action_result.data.*.commands.*.commandStatus",
                "data_type": "string",
                "example_values": ["Completed"],
            },
            {
                "data_path": "action_result.data.*.commands.*.endTime",
                "data_type": "string",
                "example_values": ["2021-09-01T09:20:33.353Z"],
            },
            {
                "data_path": "action_result.data.*.commands.*.index",
                "data_type": "numeric",
                "example_values": [0],
            },
            {
                "data_path": "action_result.data.*.commands.*.startTime",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["testmachine7"],
            },
            {
                "data_path": "action_result.data.*.creationDateTimeUtc",
                "data_type": "string",
                "example_values": ["2021-09-01T09:17:58.4219929Z"],
            },
            {
                "data_path": "action_result.data.*.errorHResult",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["81238f5f-f525-4b33-85e1-4460c5465ea4"],
            },
            {
                "data_path": "action_result.data.*.lastUpdateDateTimeUtc",
                "data_type": "string",
                "example_values": ["2021-09-01T09:21:19.11422Z"],
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "51e978e9c3cd646dde81162f0517f13b8697cfcb"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.requestSource",
                "data_type": "string",
                "example_values": ["PublicApi"],
            },
            {
                "data_path": "action_result.data.*.requestor",
                "data_type": "string",
                "example_values": ["65265db5-a7ca-4199-a425-f37ad1dd6d31"],
            },
            {
                "data_path": "action_result.data.*.requestorComment",
                "data_type": "string",
                "example_values": ["test"],
            },
            {"data_path": "action_result.data.*.scope", "data_type": "string"},
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "example_values": ["Succeeded"],
            },
            {"data_path": "action_result.data.*.title", "data_type": "string"},
            {
                "data_path": "action_result.data.*.troubleshootInfo",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.type",
                "data_type": "string",
                "example_values": ["LiveResponse"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.event_id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["6925706d-3a7e-4596-b2d7-321fca9cd965"],
                "column_name": "Event ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.summary.event_id_status",
                "data_type": "string",
                "example_values": ["Succeeded"],
            },
            {
                "data_path": "action_result.summary.file_status",
                "data_type": "string",
                "example_values": ["Succeeded"],
            },
            {
                "data_path": "action_result.summary.live_response_result",
                "data_type": "string",
            },
            {
                "data_path": "action_result.summary.vault_id",
                "data_type": "string",
                "contains": ["vault id"],
                "example_values": [
                    "7553f175dbbfa2f0830bebe8c367fe68fd40a9a4"  # pragma: allowlist secret
                ],
            },
        ],
    },
    "put_file_live_response": {
        "data": [
            {
                "data_path": "action_result.data.*.@odata.context",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://api.securitycenter.windows.com/api/$metadata#MachineActions/$entity"
                ],
            },
            {
                "data_path": "action_result.data.*.cancellationComment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationDateTimeUtc",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.cancellationRequestor",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.commands.*.command.params.*.key",
                "data_type": "string",
                "example_values": ["FileName"],
            },
            {
                "data_path": "action_result.data.*.commands.*.command.params.*.value",
                "data_type": "string",
                "contains": ["file name"],
                "example_values": ["one.txt"],
            },
            {
                "data_path": "action_result.data.*.commands.*.command.type",
                "data_type": "string",
                "example_values": ["PutFile"],
            },
            {
                "data_path": "action_result.data.*.commands.*.commandStatus",
                "data_type": "string",
                "example_values": ["Completed"],
            },
            {
                "data_path": "action_result.data.*.commands.*.endTime",
                "data_type": "string",
                "example_values": ["2021-09-01T06:43:33.717Z"],
            },
            {
                "data_path": "action_result.data.*.commands.*.index",
                "data_type": "numeric",
                "example_values": [0],
            },
            {
                "data_path": "action_result.data.*.commands.*.startTime",
                "data_type": "string",
                "example_values": ["2021-09-01T06:43:32.42Z"],
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
                "example_values": ["testmachine7"],
            },
            {
                "data_path": "action_result.data.*.creationDateTimeUtc",
                "data_type": "string",
                "example_values": ["2021-09-01T06:40:58.9203082Z"],
            },
            {
                "data_path": "action_result.data.*.errorHResult",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.externalId", "data_type": "string"},
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["30f736e4-1538-46ca-b21f-8f315b096077"],
                "column_name": "Event ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.lastUpdateDateTimeUtc",
                "data_type": "string",
                "example_values": ["2021-09-01T06:44:17.161248Z"],
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "contains": ["defender atp device id"],
                "example_values": [
                    "51e978e9c3cd646dde81162f0517f13b8697cfcb"  # pragma: allowlist secret
                ],
            },
            {
                "data_path": "action_result.data.*.requestSource",
                "data_type": "string",
                "example_values": ["PublicApi"],
            },
            {
                "data_path": "action_result.data.*.requestor",
                "data_type": "string",
                "example_values": ["65265db5-a7ca-4199-a425-f37ad1dd6d31"],
            },
            {
                "data_path": "action_result.data.*.requestorComment",
                "data_type": "string",
                "example_values": ["putfile"],
            },
            {"data_path": "action_result.data.*.scope", "data_type": "string"},
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "example_values": ["Succeeded"],
                "column_name": "Status",
                "column_order": 3,
            },
            {"data_path": "action_result.data.*.title", "data_type": "string"},
            {
                "data_path": "action_result.data.*.troubleshootInfo",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.type",
                "data_type": "string",
                "example_values": ["LiveResponse"],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.event_id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["6925706d-3a7e-4596-b2d7-321fca9cd965"],
            },
            {
                "data_path": "action_result.summary.put_file_status",
                "data_type": "string",
                "example_values": ["Succeeded"],
            },
        ],
    },
    "cancel_live_response": {
        "data": [
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "contains": ["defender atp action id"],
                "column_name": "Action ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.type",
                "data_type": "string",
                "column_name": "Action Type",
                "column_order": 1,
            },
            {"data_path": "action_result.data.*.scope", "data_type": "string"},
            {"data_path": "action_result.data.*.requestor", "data_type": "string"},
            {
                "data_path": "action_result.data.*.requestorComment",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.status",
                "data_type": "string",
                "column_name": "Status",
                "column_order": 2,
            },
            {
                "data_path": "action_result.data.*.machineId",
                "data_type": "string",
                "column_name": "Machine ID",
                "column_order": 3,
            },
            {
                "data_path": "action_result.data.*.computerDnsName",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.creationDateTimeUtc",
                "data_type": "string",
            },
            {
                "data_path": "action_result.data.*.lastUpdateDateTimeUtc",
                "data_type": "string",
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.action_taken",
                "data_type": "string",
                "example_values": ["Canceled Live Response Action"],
            }
        ],
    },
    "run_script_live_response": {
        "data": [
            {
                "data_path": "action_result.data.*.exit_code",
                "data_type": "numeric",
                "example_values": [0],
            },
            {"data_path": "action_result.data.*.script_errors", "data_type": "string"},
            {
                "data_path": "action_result.data.*.script_name",
                "data_type": "string",
                "example_values": ["script4.ps1"],
            },
            {
                "data_path": "action_result.data.*.script_output",
                "data_type": "string",
                "example_values": [
                    "Transcript started, output file is "
                    "C:\\ProgramData\\Microsoft\\Windows Defender Advanced "
                    "Threat "
                    "Protection\\Temp\\PSScriptOutputs\\PSScript_Transcript_{66D7B239-34C7-43EF-BB6D-2F6D4C03086E}.txt "
                    "x is smaller than y"
                ],
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.event_id",
                "data_type": "string",
                "contains": ["defender atp event id"],
                "example_values": ["6925706d-3a7e-4596-b2d7-321fca9cd965"],
            },
            {
                "data_path": "action_result.summary.event_id_status",
                "data_type": "string",
            },
            {
                "data_path": "action_result.summary.live_response_result",
                "data_type": "string",
            },
            {
                "data_path": "action_result.summary.script_status",
                "data_type": "string",
                "example_values": ["Succeeded"],
            },
        ],
    },
    "get_missing_kbs": {
        "data": [
            {
                "data_path": "action_result.data.*.cveAddressed",
                "data_type": "numeric",
                "example_values": [26],
            },
            {
                "data_path": "action_result.data.*.id",
                "data_type": "string",
                "example_values": ["5005033"],
                "column_name": "KB ID",
                "column_order": 0,
            },
            {
                "data_path": "action_result.data.*.machineMissedOn",
                "data_type": "numeric",
                "example_values": [1],
            },
            {
                "data_path": "action_result.data.*.name",
                "data_type": "string",
                "example_values": ["August 2021 Security Updates"],
                "column_name": "KB Name",
                "column_order": 1,
            },
            {
                "data_path": "action_result.data.*.osBuild",
                "data_type": "numeric",
                "example_values": [19042],
            },
            {
                "data_path": "action_result.data.*.productsNames",
                "data_type": "string",
                "example_values": ["windows_10"],
            },
            {
                "data_path": "action_result.data.*.url",
                "data_type": "string",
                "contains": ["url"],
                "example_values": [
                    "https://catalog.update.microsoft.com/v7/site/Search.aspx?q=KB5005033"
                ],
                "column_name": "URL",
                "column_order": 2,
            },
        ],
        "summary": [
            {
                "data_path": "action_result.summary.total_kbs",
                "data_type": "numeric",
                "example_values": [1],
            }
        ],
    },
}
