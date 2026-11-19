
import json
import os
import subprocess
from typing import Any


SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"


class WindowsSysmonEventSource:
    """Read Sysmon Event ID 1 and 11 using Windows PowerShell."""

    def __init__(
        self,
        powershell_executable: str = "powershell.exe",
        timeout: int = 30,
    ):
        if (
            not isinstance(timeout, int)
            or isinstance(timeout, bool)
            or timeout < 1
        ):
            raise ValueError("timeout must be a positive integer")

        if (
            not isinstance(powershell_executable, str)
            or not powershell_executable.strip()
        ):
            raise ValueError(
                "powershell_executable must be a non-empty string"
            )

        self.powershell_executable = powershell_executable
        self.timeout = timeout

    def read_events(
        self,
        after_record_id: int = 0,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """Read events newer than the supplied Windows record ID."""

        if (
            not isinstance(after_record_id, int)
            or isinstance(after_record_id, bool)
            or after_record_id < 0
        ):
            raise ValueError(
                "after_record_id must be a non-negative integer"
            )

        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= 1000
        ):
            raise ValueError(
                "limit must be an integer between 1 and 1000"
            )

        if os.name != "nt":
            raise RuntimeError(
                "Windows Sysmon Event Log collection requires Windows"
            )

        xpath = (
            "*[System[(EventID=1 or EventID=11) "
            f"and (EventRecordID > {after_record_id})]]"
        )

        script = f"""
$ErrorActionPreference = 'Stop'
try {{
    $events = @(Get-WinEvent `
        -LogName '{SYSMON_LOG}' `
        -FilterXPath '{xpath}' `
        -MaxEvents {limit} `
        -Oldest `
        -ErrorAction Stop)
}}
catch {{
    if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') {{
        '[]'
        exit 0
    }}
    throw
}}
$items = @(
    $events |
    Sort-Object RecordId |
    ForEach-Object {{
        [PSCustomObject]@{{
            record_id = [long]$_.RecordId
            xml = $_.ToXml()
        }}
    }}
)
ConvertTo-Json -InputObject $items -Compress -Depth 3
"""

        try:
            completed = subprocess.run(
                [
                    self.powershell_executable,
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    script,
                ],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )

        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Sysmon Event Log query timed out "
                f"after {self.timeout} seconds"
            ) from exc

        except OSError as exc:
            raise RuntimeError(
                f"PowerShell execution failed: {exc}"
            ) from exc

        if completed.returncode != 0:
            raise RuntimeError(
                "Sysmon Event Log query failed: "
                + completed.stderr.strip()
            )

        try:
            records = json.loads(
                completed.stdout or "[]"
            )

        except json.JSONDecodeError as exc:
            raise ValueError(
                "Invalid response from Windows Event Log"
            ) from exc

        if isinstance(records, dict):
            records = [records]

        if not isinstance(records, list):
            raise ValueError(
                "Expected a list of Sysmon records"
            )

        validated = []
        seen_ids = set()

        for record in records:
            if not isinstance(record, dict):
                raise ValueError(
                    "Invalid Sysmon record"
                )

            record_id = record.get("record_id")
            xml = record.get("xml")

            if (
                not isinstance(record_id, int)
                or isinstance(record_id, bool)
                or record_id <= after_record_id
            ):
                raise ValueError(
                    "Invalid Sysmon record ID"
                )

            if record_id in seen_ids:
                raise ValueError(
                    f"Duplicate record_id: {record_id}"
                )

            seen_ids.add(record_id)

            if (
                not isinstance(xml, str)
                or not xml.strip()
            ):
                raise ValueError(
                    "Missing Sysmon XML"
                )

            validated.append({
                "record_id": record_id,
                "xml": xml,
            })

        return sorted(
            validated,
            key=lambda item: item["record_id"],
        )