"""Explicit adapters. Payload generation is offline; sending is opt-in."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import urlparse
import requests
from .engine import ROOT, timestamp
from .importers import load_events
from .report import write_json

def fetch_public(manifest_path, out):
    manifest = json.loads(Path(manifest_path).read_text())
    url = manifest["url"]; parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname != "media.githubusercontent.com" or not parsed.path.startswith("/media/splunk/attack_data/"):
        raise ValueError("Public fetch supports pinned Splunk attack_data media URLs only")
    revision = manifest["revision"]
    if len(revision) != 40 or revision not in parsed.path.split("/"): raise ValueError("Require immutable 40-character revision in URL")
    if manifest.get("license") != "Apache-2.0": raise ValueError("Manifest license review required")
    response = requests.get(url, timeout=30, stream=True, allow_redirects=False)
    response.raise_for_status()
    if response.status_code != 200: raise ValueError("Dataset redirects are not followed")
    data = bytearray()
    for chunk in response.iter_content(65536):
        data.extend(chunk)
        if len(data) > 20*1024*1024: raise ValueError("Public dataset exceeds 20 MiB limit")
    digest = hashlib.sha256(data).hexdigest()
    if digest != manifest["sha256"]: raise ValueError("Dataset SHA256 mismatch; no output written")
    out = Path(out);out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(data)
    events, evidence = load_events(out)
    evidence.update(source=manifest, retrieved_at=datetime.now(timezone.utc).isoformat(), kind="independent_public_dataset", label_scope="Dataset technique label; individual events are not independently adjudicated")
    write_json(out.with_suffix(".provenance.json"), evidence)
    return evidence

def payload(events, target):
    if target == "splunk":
        return [{"time":timestamp(e["TimeCreated"]),"host":e["Computer"],"index":"adlab","sourcetype":"selbi:adlab","event":e} for e in events]
    if target == "sentinel":
        return [{**{k:e.get(k) for k in SENTINEL_FIELDS}, "TimeGenerated":e["TimeCreated"]} for e in events]
    raise ValueError("Unknown target")

SENTINEL_FIELDS = ["RecordId","TimeCreated","Computer","Provider","Channel","EventID","LogonType","IpAddress","TargetUserName","SubjectUserName","ServiceName","TicketEncryptionType","Status","Image","ParentImage","CommandLine","SourceImage","TargetImage","GrantedAccess","ImagePath","ScriptBlockText","ShareName","AccessMask","RelativeTargetName","TargetFilename","User"]

def send(events, target, endpoint, token_env):
    parsed=urlparse(endpoint)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password: raise ValueError("HTTPS endpoint without URL credentials required")
    token=os.environ.get(token_env)
    if not token: raise ValueError(f"Missing token environment variable {token_env}")
    records=payload(events,target)
    # Bound each encoded request before sending anything. This cap is deliberately
    # conservative for custom-log APIs and protects against a huge single event.
    prepared=[];current=[];size=2
    for record in records:
        encoded=json.dumps(record,ensure_ascii=False,separators=(",", ":")).encode("utf-8")
        if len(encoded)+2>900*1024: raise ValueError("A record exceeds the 900 KiB request budget; no batches sent")
        if current and (len(current)>=100 or size+len(encoded)+1>900*1024):
            prepared.append(current);current=[];size=2
        current.append(encoded);size+=len(encoded)+1
    if current:prepared.append(current)
    batches=0;accepted_events=0
    for batch in prepared:
        body=b"\n".join(batch) if target=="splunk" else b"["+b",".join(batch)+b"]"
        headers={"Content-Type":"application/json","Authorization":("Splunk " if target=="splunk" else "Bearer ")+token}
        try:
            r=requests.post(endpoint,headers=headers,timeout=30,allow_redirects=False,data=body)
            r.raise_for_status()
            if r.status_code not in (200,204): raise ValueError(f"Unexpected ingestion status {r.status_code}")
            if target=="splunk" and r.json().get("code") != 0: raise ValueError("Splunk HEC did not accept batch")
        except (requests.RequestException,ValueError) as exc:
            # Do not echo provider bodies/URLs which can contain secrets. Failure
            # after a timeout can still have reached the service: never auto-retry.
            reason=str(exc) if isinstance(exc,ValueError) else type(exc).__name__
            raise ValueError(f"Batch {batches+1} failed after {batches} accepted batch(es), {accepted_events} accepted event(s): {reason}. Current batch acceptance is unknown; reconcile RecordId before retry.") from None
        batches+=1;accepted_events+=len(batch)
    return {"accepted_batches":batches,"events_submitted":accepted_events,"query_validation":False,"warning":"API acceptance does not establish indexing or query correctness. Reconcile RecordId before retrying partial failures."}
