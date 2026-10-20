import base64
import csv
import hashlib
import html
import json
from pathlib import Path
import re
import time
import shutil
from datetime import datetime, timezone
from .engine import ROOT, replay
from .importers import load_events

def write_json(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")

def bundled_fonts(output):
    """Embed licensed fonts so copied file:// reports need no font-origin access."""
    assets = Path(__file__).parent / "assets"
    target = Path(output) / "assets"
    target.mkdir(parents=True, exist_ok=True)
    faces = []
    for name, weight in (("Regular", 400), ("Medium", 500), ("SemiBold", 600)):
        source = assets / f"IBMPlexSans-{name}.woff2"
        encoded = base64.b64encode(source.read_bytes()).decode("ascii")
        faces.append(f"@font-face{{font-family:'IBM Plex Sans';font-style:normal;"
                     f"font-weight:{weight};font-display:swap;"
                     f"src:url(data:font/woff2;base64,{encoded}) format('woff2')}}")
    for source in assets.iterdir():
        if source.is_file() and source.resolve() != (target / source.name).resolve():
            shutil.copyfile(source, target / source.name)
    return "\n".join(faces)

def build_report(rules, attack_path, benign_path, output):
    output = Path(output); output.mkdir(parents=True, exist_ok=True)
    attack, ap = load_events(attack_path); benign, bp = load_events(benign_path)
    start = time.perf_counter()
    aa, ba = replay(rules, attack), replay(rules, benign)
    elapsed = time.perf_counter() - start
    by_rule = []
    for r in rules:
        attack_alerts = [a for a in aa if a["rule_id"] == r["id"]]
        benign_alerts = [a for a in ba if a["rule_id"] == r["id"]]
        by_rule.append({"id":r["id"],"slug":r["slug"],"title":r["title"],"level":r["level"],
                        "attack_alerts":len(attack_alerts),"benign_alerts":len(benign_alerts),
                        "benign_events_matched":len({eid for a in benign_alerts for eid in a["event_ids"]}),
                        "techniques":[t[7:].upper() for t in r["tags"] if re.fullmatch(r"attack\.t\d{4}(\.\d{3})?",t)]})
    benign_hit = {eid for a in ba for eid in a["event_ids"]}
    result = {"generated_at":datetime.now(timezone.utc).isoformat(),"boundary":"Local Python rule replay. Inputs are user-designated positive/benign sets; default fixtures are authored synthetic. Alerts do not establish compromise.",
              "inputs":[ap,bp],"rules":len(rules),"attack_events":len(attack),"benign_events":len(benign),
              "rules_triggered":sum(x["attack_alerts"]>0 for x in by_rule),"attack_alerts":len(aa),"benign_alerts":len(ba),
              "benign_events_matched":len(benign_hit),"benign_event_signal_rate":len(benign_hit)/len(benign),
              "unique_techniques":len({t for x in by_rule for t in x["techniques"]}),"replay_elapsed_seconds":elapsed,
              "per_rule":by_rule,"native_siem_execution":False,"live_windows_capture":False}
    write_json(output / "summary.json",result);write_json(output / "alerts.json", aa);write_json(output / "benign-alerts.json",ba)
    with (output / "matrix.csv").open("w",newline="") as f:
        w=csv.DictWriter(f,fieldnames=list(by_rule[0]));w.writeheader();w.writerows(by_rule)
    techniques = sorted({t for x in by_rule for t in x["techniques"]})
    write_json(output / "navigator-layer.json",{"name":"Selbi AD lab — locally replayed candidates","versions":{"layer":"4.5","navigator":"5.1.0"},"domain":"enterprise-attack",
               "description":"Coverage of authored detections, not complete ATT&CK coverage or production validation.","techniques":[{"techniqueID":t,"color":"#237a68","comment":"Local replay coverage only","enabled":True} for t in techniques],"legendItems":[{"label":"Authored rule replayed locally","color":"#237a68"}]})
    known_fixtures = json.loads((ROOT / "fixtures/provenance.json").read_text()).get("sha256", {})
    synthetic = ap["sha256"] == known_fixtures.get("attack.jsonl") and bp["sha256"] == known_fixtures.get("benign.jsonl")
    result["input_origin"] = "bundled-synthetic-verified-by-sha256" if synthetic else "operator-supplied-provenance-unverified"
    write_json(output / "summary.json", result)
    # Ship linked notes and exports with the report so --out works outside the project.
    linked = [*sorted((ROOT / "rules").glob("*.yml")), *sorted((ROOT / "docs/rules").glob("*.md")),
              *sorted((ROOT / "queries/splunk").glob("*.spl")), *sorted((ROOT / "queries/kql").glob("*.kql"))]
    linked += [ROOT / "docs" / name for name in ("lab-setup.md", "siem.md", "sources.md", "emulation.md")]
    for source in linked:
        if source.is_file():
            target = output / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.resolve() != target.resolve(): shutil.copyfile(source, target)
    details = []
    for r, row in zip(rules, by_rule):
        queries = {}
        for backend, ext in (("splunk", "spl"), ("kql", "kql")):
            path = ROOT / "queries" / backend / (r["slug"] + "." + ext)
            queries[backend] = path.read_text() if path.exists() else "Query export is unavailable. Run python -m adlab translate, then regenerate this report."
        details.append({**row, "description": r["description"], "falsepositives": r.get("falsepositives", []),
                        "path": r["path"], "kind": "Correlation" if "correlation" in r else "Event rule",
                        "queries": queries, "source": r.get("logsource", r.get("correlation"))})
    package = {"summary": result, "rules": details, "alerts": aa, "benignAlerts": ba,
               "events": {"positive": {e["RecordId"]: e for e in attack}, "benign": {e["RecordId"]: e for e in benign}}, "synthetic": synthetic}
    # Escape HTML delimiters inside the JSON script data, including user-controlled event text.
    data = json.dumps(package, ensure_ascii=False).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    template = (Path(__file__).parent / "report-template.html").read_text()
    (output / "report.html").write_text(template.replace("__FONT_CSS__", bundled_fonts(output)).replace("__REPORT_DATA__", data))
    return result
