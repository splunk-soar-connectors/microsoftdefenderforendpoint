**Unreleased**

* Migrated all 58 legacy actions to Splunk SOAR SDK 6.1.2 and added the generic `make_request` action.
* The SDK runtime requires SOAR 7.0.0 or later.
* Validate domain indicators before constructing request URLs.
* Preserve zero exposure scores in action outputs and summaries.
* Fix vulnerability CVSS filters to use numeric `cvssV3` comparisons, including zero scores.
* Fail requests with malformed nonempty JSON responses instead of treating them as successful data; preserve valid empty responses.
* Distinguish RunScript result retrieval failures from parsing failures and retain the event ID, status, and failure details in failed results.
* Resume alert polling by timestamp and ID instead of mutable page offsets; repair the first-run time-range constant.
* Import legacy polling checkpoints into SDK ingestion state. Existing offset windows restart safely; see the SDK upgrade guidance.
* Preserve legacy raw API data values and fields in SDK action results while publishing concrete SDK-compatible output types.
* Correct generated output metadata for nested `relatedUser`, `vmMetadata`, `certificateInfo`, and `relatedFileInfo` objects: remove their scalar parent paths and keep their child paths. This changes manifest datapaths only; the returned object payloads are unchanged.
* Preserve the `get_file_info` table's legacy column order with explicit row fields. The table now reads `Status`, `File Hash`, then the file details. SDK table metadata publishes `status` and `file_hash` at `action_result.data.*.status` and `action_result.data.*.file_hash`; `action_result.status` and `action_result.parameter.file_hash` remain available at their existing paths. Each data row gains the two table fields.
* Preserve the `delete_indicator` table's `Indicator ID` and `Status` columns with a one-row compatibility record. The indicator ID remains in `action_result.parameter.indicator_id`; this adds `action_result.data.*.status`. The action message and top-level status remain unchanged.
* Align `get_file_live_response` and `put_file_live_response` table column metadata with the SDK's parameter-first ordering. Their output datapaths and values are unchanged.
* Restore the legacy related-device widget for file, user, and domain lookups. It reads request values from `action_result.parameter` and device rows from `action_result.data`; no action-result datapaths change.
* Show the alert ID in the get-alert custom widget while preserving its existing action-result datapaths.
* Add output metadata for `action_taken` summary values emitted by `get_alert_user`, `get_alert_files`, `get_alert_ips`, `get_alert_domains`, `create_alert`, `get_indicator`, `update_indicator`, `update_indicator_batch`, `get_file_alerts`, `get_device_alerts`, `get_user_alerts`, and `get_domain_alerts`, plus `total_results` for `get_alert_files`, `get_alert_ips`, `get_alert_domains`, `update_indicator_batch`, `get_file_alerts`, `get_device_alerts`, `get_user_alerts`, and `get_domain_alerts`. These summary values were already returned by the handlers but missing from the legacy manifest.
* Refresh and retry once when Defender rejects a bearer token with HTTP 401; do not retry other request failures.
* Accept computer names for the read-only get-device-details action while continuing to validate other machine paths as device IDs.
* Retain accepted event IDs, latest known response data, and summaries when follow-up polling (including antivirus scans) or live-response result handling fails. Keep successful no-data responses empty.
* Preserve zero secure scores, reject blank software IDs, return earlier device records if a later lookup fails, and escape apostrophes in structured OData string filters.
* Keep test connectivity on the alerts endpoint used by the legacy app.
