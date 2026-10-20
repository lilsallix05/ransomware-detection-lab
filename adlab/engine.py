"""Bounded Sigma event evaluator and exact distinct-value sliding correlation.

The evaluator intentionally implements only the subset used by this pack. Rules
are also parsed by pySigma. Unsupported syntax fails validation, never silently
matches or falls back to executing Python.
"""
from __future__ import annotations
import ast
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
import re
import uuid
import yaml
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parents[1]

def timestamp(value):
    dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("TimeCreated must include a timezone")
    return dt.timestamp()

def condition(expression, selections):
    tree = ast.parse(expression, mode="eval")
    def walk(node):
        if isinstance(node, ast.Expression): return walk(node.body)
        if isinstance(node, ast.Name) and node.id in selections: return selections[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not): return not walk(node.operand)
        if isinstance(node, ast.BoolOp) and isinstance(node.op, (ast.And, ast.Or)):
            values = [walk(x) for x in node.values]
            return all(values) if isinstance(node.op, ast.And) else any(values)
        raise ValueError(f"Unsupported or unknown condition: {expression}")
    return walk(tree)

def field_match(event, expression, expected):
    field, *mods = expression.split("|")
    supported = {"contains", "startswith", "endswith", "all"}
    if set(mods) - supported or len(set(mods) & (supported - {"all"})) > 1:
        raise ValueError(f"Unsupported modifiers in {expression}")
    if field not in event or event[field] is None: return False
    values = expected if isinstance(expected, list) else [expected]
    observed = event[field] if isinstance(event[field], list) else [event[field]]
    def matches(actual, value):
        if not isinstance(value, (str, int, float, bool)):
            raise ValueError("Unsupported Sigma value")
        a, b = str(actual).casefold(), str(value).casefold()
        if "contains" in mods: return b in a
        if "startswith" in mods: return a.startswith(b)
        if "endswith" in mods: return a.endswith(b)
        # Wildcards intentionally not accepted in this profile; literal equality.
        return a == b
    results = [any(matches(a, v) for a in observed) for v in values]
    return all(results) if "all" in mods else any(results)

def source_matches(rule, event):
    source = rule["logsource"]
    category = source.get("category")
    service = source.get("service")
    if source.get("product") != "windows": return False
    if category in {"process_creation", "process_access", "file_event"}:
        eid = {"process_creation": 1, "process_access": 10, "file_event": 11}[category]
        return event.get("Provider") == "Microsoft-Windows-Sysmon" and event.get("EventID") == eid
    channels = {"security": "Security", "system": "System", "powershell": "Microsoft-Windows-PowerShell/Operational"}
    providers = {"security": "Microsoft-Windows-Security-Auditing", "system": "Service Control Manager", "powershell": "Microsoft-Windows-PowerShell"}
    return event.get("Channel") == channels.get(service) and event.get("Provider") == providers.get(service)

def matches(rule, event):
    if not source_matches(rule, event): return False
    detection = rule["detection"]
    selections = {name: all(field_match(event, key, val) for key, val in fields.items())
                  for name, fields in detection.items() if name != "condition"}
    return condition(detection["condition"], selections)

def load_rules(directory=ROOT / "rules"):
    paths = sorted(Path(directory).glob("*.yml"))
    if not paths: raise ValueError("No rules found")
    docs = [yaml.safe_load(p.read_text()) for p in paths]
    SigmaCollection.from_yaml("\n---\n".join(p.read_text() for p in paths))
    ids = set()
    for rule, path in zip(docs, paths):
        uuid.UUID(rule["id"])
        if rule["id"] in ids: raise ValueError("Duplicate rule ID")
        ids.add(rule["id"])
        rule["path"] = str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)
        rule["slug"] = path.stem
        if "correlation" in rule:
            c = rule["correlation"]
            if c["type"] != "value_count" or c["timespan"] != "1m" or set(c["condition"]) != {"gte", "field"}:
                raise ValueError("Only one-minute gte value_count correlations supported")
            if c["group-by"] != ["Computer", "Image"] or c["condition"]["field"] != "TargetFilename" or len(c["rules"]) != 1: raise ValueError("Unsupported correlation fields; profile requires Computer/Image and TargetFilename")
            if not c["group-by"] or not isinstance(c["condition"]["gte"], int) or isinstance(c["condition"]["gte"], bool) or c["condition"]["gte"] < 1:
                raise ValueError("Invalid correlation grouping or threshold")
            continue
        source = rule["logsource"]
        if source.get("product") != "windows" or not (
            source.get("category") in {"process_creation", "process_access", "file_event"}
            or source.get("service") in {"security", "system", "powershell"}
        ): raise ValueError("Unsupported logsource in bounded replay profile")
        d = rule["detection"]
        condition(d["condition"], {k: False for k in d if k != "condition"})
        for name, selection in d.items():
            if name == "condition": continue
            if not isinstance(selection, dict): raise ValueError("Only mapping selections supported")
            for key, val in selection.items():
                for value in val if isinstance(val, list) else [val]:
                    if value is None or (isinstance(value, str) and any(x in value for x in ("*", "?"))):
                        raise ValueError("Null and wildcard values unsupported by this replay profile")
                field_match({key.split("|")[0]: "probe"}, key, val)
    for r in docs:
        if "correlation" in r and set(r["correlation"]["rules"]) - ids:
            raise ValueError("Missing correlation dependency")
    return docs

def replay(rules, events):
    events = sorted(events, key=lambda e: (timestamp(e["TimeCreated"]), e["RecordId"]))
    if len({e["RecordId"] for e in events}) != len(events): raise ValueError("Duplicate RecordId; import with unique identifiers")
    alerts, per_rule = [], defaultdict(list)
    for event in events:
        for rule in rules:
            if "detection" in rule and matches(rule, event):
                alert = {"rule_id": rule["id"], "slug": rule["slug"], "title": rule["title"], "level": rule["level"],
                         "time": event["TimeCreated"], "computer": event["Computer"], "event_ids": [event["RecordId"]],
                         "techniques": [t[7:].upper() for t in rule["tags"] if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?", t)]}
                alerts.append(alert); per_rule[rule["id"]].append(event)
    for rule in rules:
        if "correlation" not in rule: continue
        c = rule["correlation"]; groups = defaultdict(deque)
        candidates = {e["RecordId"]: e for rid in c["rules"] for e in per_rule[rid]}
        for e in sorted(candidates.values(), key=lambda x: (timestamp(x["TimeCreated"]), x["RecordId"])):
            if any(e.get(k) in (None, "") for k in c["group-by"] + [c["condition"]["field"]]): continue
            key = tuple(str(e[k]).casefold() for k in c["group-by"])
            window = groups[key]; now = timestamp(e["TimeCreated"])
            while window and timestamp(window[0]["TimeCreated"]) < now - 60: window.popleft()
            field = c["condition"]["field"]; threshold = c["condition"]["gte"]
            before = len({str(v[field]).casefold() for v in window})
            window.append(e)
            count = len({str(v[field]).casefold() for v in window})
            # Emit on threshold crossing; re-arm after the window falls below it.
            if before < threshold <= count:
                alerts.append({"rule_id": rule["id"], "slug": rule["slug"], "title": rule["title"], "level": rule["level"],
                               "time": e["TimeCreated"], "computer": e["Computer"], "event_ids": [v["RecordId"] for v in window],
                               "distinct_files": count, "window_seconds": 60, "techniques": ["T1486"]})
    return sorted(alerts, key=lambda a: (timestamp(a["time"]), a["slug"]))
