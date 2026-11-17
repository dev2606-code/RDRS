\
"""Parse Windows Sysmon XML events safely."""

import xml.etree.ElementTree as ET

from pathlib import PureWindowsPath
from typing import Any


SUPPORTED_EVENT_IDS = {1, 11}


def _get_process_id(value: str | None) -> int | None:
    if not value:
        return None

    try:
        return int(value, 0)
    except ValueError:
        try:
            return int(value, 10)
        except ValueError:
            return None


def _get_record_id(value: str | None) -> int | None:
    """Parse a non-negative Windows EventRecordID."""
    if value is None or not value.strip():
        return None

    try:
        record_id = int(value.strip(), 10)
    except ValueError as exc:
        raise ValueError("Invalid Sysmon EventRecordID") from exc

    if record_id < 0:
        raise ValueError("Sysmon EventRecordID cannot be negative")

    return record_id


def parse_sysmon_event(xml_event: str) -> dict[str, Any] | None:
    """Parse Sysmon Process Create and File Create XML events."""

    try:
        root = ET.fromstring(xml_event)
    except ET.ParseError as exc:
        raise ValueError("Invalid Sysmon XML event") from exc

    event_id = None
    timestamp = None
    computer = None
    channel = None
    record_id = None
    event_data = {}

    for element in root.iter():
        tag = element.tag.split("}")[-1]

        if tag == "EventID" and element.text:
            try:
                event_id = int(element.text.strip())
            except ValueError as exc:
                raise ValueError("Invalid Sysmon Event ID") from exc

        elif tag == "TimeCreated":
            timestamp = element.attrib.get("SystemTime")

        elif tag == "Computer":
            computer = (element.text or "").strip() or None

        elif tag == "Channel":
            channel = (element.text or "").strip() or None

        elif tag == "EventRecordID":
            record_id = _get_record_id(element.text)

        elif tag == "Data":
            name = element.attrib.get("Name")
            if name:
                event_data[name] = element.text or ""

    if event_id not in SUPPORTED_EVENT_IDS:
        return None

    image = event_data.get("Image") or None
    username = event_data.get("User") or None

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "computer": computer,
        "channel": channel,
        "record_id": record_id,
        "process_guid": event_data.get("ProcessGuid") or None,
        "process_id": _get_process_id(
            event_data.get("ProcessId")
        ),
        "process_name": (
            PureWindowsPath(image).name if image else None
        ),
        "process_path": image,
        "username": username,
        "command_line": event_data.get("CommandLine") or None,
        "target_filename": (
            event_data.get("TargetFilename") or None
        ),
    }
