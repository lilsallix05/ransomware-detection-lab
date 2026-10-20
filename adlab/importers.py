"""Normalize JSONL, Splunk JSON exports and XML Windows events. No EVTX parser."""
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET
from .engine import ROOT, timestamp

MAX_BYTES = 100 * 1024 * 1024
NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

def xml_event(text):
    if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper(): raise ValueError("XML declarations are not allowed")
    root = ET.fromstring(text)
    # Namespace-independent parsing handles exported and rendered XML.
    for elem in root.iter(): elem.tag = elem.tag.split("}")[-1]
    system = root.find("System")
    if system is None: raise ValueError("Missing System element")
    get = lambda name: system.findtext(name)
    event = {"Provider": system.find("Provider").get("Name"), "EventID": get("EventID"),
             "Channel": get("Channel"), "Computer": get("Computer"), "EventRecordID": get("EventRecordID"),
             "TimeCreated": system.find("TimeCreated").get("SystemTime")}
    for node in root.findall("./EventData/Data"):
        if node.get("Name"): event[node.get("Name")] = node.text or ""
    return event

def normalize(raw, ordinal=1, source_hash="local"):
    if not isinstance(raw, dict): raise ValueError("Event must be an object")
    if "result" in raw: raw = raw["result"]
    if not isinstance(raw, dict): raise ValueError("Splunk result must be an object")
    if "_raw" in raw:
        if not isinstance(raw["_raw"], str): raise ValueError("_raw must be text")
        raw = xml_event(raw["_raw"]) if raw["_raw"].lstrip().startswith("<") else json.loads(raw["_raw"])
    if not isinstance(raw, dict): raise ValueError("Decoded event must be an object")
    event = dict(raw)
    # Winlogbeat/Elastic exports keep the original event_data fields.
    if isinstance(raw.get("winlog"), dict):
        w = raw["winlog"]
        event.update(w.get("event_data", {}))
        event.update(EventID=w.get("event_id"), Provider=w.get("provider_name"), Channel=w.get("channel"),
                     Computer=w.get("computer_name"), EventRecordID=w.get("record_id"), TimeCreated=raw.get("@timestamp"))
    for new, old in {"EventID": "EventCode", "Computer": "ComputerName", "TimeCreated": "UtcTime", "Provider": "SourceName"}.items():
        if not event.get(new) and old in event: event[new] = event[old]
    for required in ("EventID", "Provider", "Channel", "Computer", "TimeCreated"):
        if event.get(required) in (None, ""): raise ValueError(f"Missing required field {required}")
    for required in ("Provider", "Channel", "Computer", "TimeCreated"):
        if not isinstance(event[required], str) or not event[required].strip(): raise ValueError(f"{required} must be nonempty text")
    if isinstance(event["EventID"], bool): raise ValueError("EventID must be an integer")
    event["EventID"] = int(event["EventID"])
    if not 0 <= event["EventID"] <= 65535: raise ValueError("EventID outside Windows event range")
    timestamp(event["TimeCreated"])
    for numeric in ("LogonType",):
        if event.get(numeric) not in (None, ""): event[numeric] = int(event[numeric])
    if event.get("RecordId"):
        event["RecordId"] = str(event["RecordId"])
    elif event.get("EventRecordID") not in (None, ""):
        native_id = str(event["EventRecordID"])
        if not native_id.isdigit(): raise ValueError("EventRecordID must be an unsigned integer")
        # Include timestamp for channel resets; preserve identity across overlapping exports.
        identity = [event["Computer"].casefold(), event["Channel"].casefold(), event["Provider"].casefold(), native_id, timestamp(event["TimeCreated"])]
        event["RecordId"] = "win:" + hashlib.sha256(json.dumps(identity,separators=(",", ":")).encode()).hexdigest()[:24]
    else:
        event["RecordId"] = f"{source_hash[:12]}:{ordinal}"
    return event

def display_path(path):
    """Provenance label without the operator's home or project directory."""
    resolved = Path(path).resolve()
    return resolved.relative_to(ROOT).as_posix() if resolved.is_relative_to(ROOT) else resolved.name

def load_events(path, *, allow_rejects=False):
    path = Path(path)
    if path.stat().st_size > MAX_BYTES: raise ValueError("Input exceeds 100 MiB limit")
    data = path.read_bytes()
    if len(data) > MAX_BYTES: raise ValueError("Input exceeds 100 MiB limit")
    digest = hashlib.sha256(data).hexdigest()
    text = data.decode("utf-8-sig")
    events, rejects = [], []
    if "<Event" in text and not text.lstrip().startswith(("{", "[")):
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper(): raise ValueError("Unsafe XML declaration")
        chunks = re.findall(r"<Event(?:\s[^>]*)?>.*?</Event>", text, re.S)
        if not chunks: raise ValueError("No Windows Event elements found")
        residual = re.sub(r"<Event(?:\s[^>]*)?>.*?</Event>", "", text, flags=re.S)
        if re.search(r"<Event(?:\s|>|$)", residual): raise ValueError("Truncated XML Event")
        objects = [(i, c, True) for i, c in enumerate(chunks, 1)]
    elif text.lstrip().startswith("["):
        objects = [(i, obj, False) for i, obj in enumerate(json.loads(text), 1)]
    else:
        objects = [(i, line, False) for i, line in enumerate(text.splitlines(), 1) if line.strip()]
    for number, obj, is_xml in objects:
        try:
            if is_xml: obj = xml_event(obj)
            elif isinstance(obj, str): obj = json.loads(obj)
            events.append(normalize(obj, number, digest))
        except (ValueError, TypeError, AttributeError, ET.ParseError) as exc:
            rejects.append({"record": number, "reason": str(exc)})
    if rejects and not allow_rejects: raise ValueError(f"Rejected {len(rejects)} record(s): {rejects[:3]}")
    if not events: raise ValueError("No usable events")
    if len({e["RecordId"] for e in events}) != len(events): raise ValueError("Duplicate RecordId in input")
    return events, {"path": display_path(path), "sha256": digest, "accepted": len(events), "rejected": rejects}
