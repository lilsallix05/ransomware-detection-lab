"""pySigma backend translation with explicit normalized ingestion schema."""
import json
from pathlib import Path
from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from sigma.backends.kusto import KustoBackend
from .engine import ROOT

def source_fields(rule):
    src = rule["logsource"]
    category = src.get("category")
    if category:
        return {"Provider": "Microsoft-Windows-Sysmon", "EventID": {"process_creation": 1, "process_access": 10, "file_event": 11}[category]}
    s = src["service"]
    return {"Channel": {"security": "Security", "system": "System", "powershell": "Microsoft-Windows-PowerShell/Operational"}[s],
            "Provider": {"security": "Microsoft-Windows-Security-Auditing", "system": "Service Control Manager", "powershell": "Microsoft-Windows-PowerShell"}[s]}

def translate(rules, out=ROOT / "queries"):
    out = Path(out)
    generated, predicates = [], {}
    for r in rules:
        if "detection" not in r: continue
        spl = SplunkBackend().convert_rule(SigmaRule.from_yaml((ROOT / r["path"]).read_text()))[0]
        kql = KustoBackend().convert_rule(SigmaRule.from_yaml((ROOT / r["path"]).read_text()))[0]
        src = source_fields(r)
        sp_src = " ".join(f"{k}={json.dumps(v)}" for k,v in src.items())
        kq_src = " and ".join(f"{k} == {json.dumps(v)}" for k,v in src.items())
        predicates[r["id"]] = (f"index=adlab sourcetype=selbi:adlab {sp_src} ({spl})", f"SelbiADLab_CL\n| where {kq_src}\n| where {kql}")
    for r in rules:
        if "correlation" in r:
            c = r["correlation"]; spl, kql = predicates[c["rules"][0]]
            # Rolling time, not bin(): bursts spanning clock-minute boundaries remain visible.
            spl += ('\n| eval _time=coalesce(_time,strptime(TimeCreated, "%Y-%m-%dT%H:%M:%S.%N%:z"),strptime(TimeCreated, "%Y-%m-%dT%H:%M:%S%:z"),strptime(TimeCreated, "%Y-%m-%dT%H:%M:%S.%NZ"),strptime(TimeCreated, "%Y-%m-%dT%H:%M:%SZ")), HostKey=lower(Computer), ImageKey=lower(Image), FileKey=lower(TargetFilename)'
                    '\n| where isnotnull(_time) AND isnotnull(HostKey) AND isnotnull(ImageKey) AND isnotnull(FileKey)'
                    '\n| sort 0 _time RecordId'
                    '\n| streamstats time_window=60s dc(FileKey) as distinct_files by HostKey ImageKey'
                    f'\n| where distinct_files >= {c["condition"]["gte"]}')
            kql = "let candidates = materialize(\n" + kql + "\n| where isnotempty(Computer) and isnotempty(Image) and isnotempty(TargetFilename)\n| project TimeGenerated=todatetime(TimeCreated), RecordId, HostKey=tolower(Computer), ImageKey=tolower(Image), FileKey=tolower(TargetFilename)\n);\ncandidates\n| project Anchor=TimeGenerated, AnchorId=RecordId, HostKey, ImageKey\n| join kind=inner (candidates | project Observed=TimeGenerated, HostKey, ImageKey, FileKey) on HostKey, ImageKey\n| where Observed between ((Anchor - 1m) .. Anchor)\n| summarize distinct_files=count_distinct(FileKey) by Anchor, AnchorId, HostKey, ImageKey\n| where distinct_files >= " + str(c["condition"]["gte"])
        else: spl, kql = predicates[r["id"]]
        for backend, ext, body in [("splunk", "spl", spl), ("kql", "kql", kql)]:
            directory = out / backend; directory.mkdir(parents=True, exist_ok=True)
            path = directory / (r["slug"] + "." + ext)
            path.write_text(body + "\n")
            generated.append({"rule_id":r["id"],"backend":backend,"path":str(path),"validation":"generated-not-native-executed", "method":"explicit rolling-window translator" if "correlation" in r else "pySigma backend"})
    return generated
