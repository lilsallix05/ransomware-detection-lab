import argparse
import json
from pathlib import Path
import sys
from .engine import ROOT, load_rules, replay
from .importers import load_events
from .integrations import fetch_public, payload, send
from .report import build_report, write_json
from .translate import translate

def main(argv=None):
    parser=argparse.ArgumentParser(description="Selbi AD detection-as-code lab: offline by default")
    sub=parser.add_subparsers(dest="command",required=True)
    sub.add_parser("validate",help="Parse all rules with pySigma and validate the replay profile")
    trans=sub.add_parser("translate");trans.add_argument("--out",type=Path,default=ROOT/"queries")
    rep=sub.add_parser("report");rep.add_argument("--attack",type=Path,default=ROOT/"fixtures/attack.jsonl");rep.add_argument("--benign",type=Path,default=ROOT/"fixtures/benign.jsonl");rep.add_argument("--out",type=Path,default=ROOT/"evidence/replay")
    run=sub.add_parser("replay");run.add_argument("input",type=Path);run.add_argument("--out",type=Path,required=True)
    imp=sub.add_parser("import");imp.add_argument("input",type=Path);imp.add_argument("--out",type=Path,required=True);imp.add_argument("--allow-rejects",action="store_true")
    fetch=sub.add_parser("fetch-public");fetch.add_argument("--manifest",type=Path,default=ROOT/"fixtures/public-dataset.json");fetch.add_argument("--out",type=Path,default=ROOT/"work/public-kerberoasting.xml")
    adapter=sub.add_parser("siem");adapter.add_argument("target",choices=["splunk","sentinel"]);adapter.add_argument("input",type=Path);adapter.add_argument("--out",type=Path,required=True);adapter.add_argument("--send",action="store_true");adapter.add_argument("--endpoint");adapter.add_argument("--token-env",default="ADLAB_SIEM_TOKEN")
    args=parser.parse_args(argv)
    try:
        if args.command=="import":
            events, result=load_events(args.input,allow_rejects=args.allow_rejects)
            args.out.parent.mkdir(parents=True,exist_ok=True)
            args.out.write_text("".join(json.dumps(e)+"\n" for e in events));write_json(args.out.with_suffix(".provenance.json"),result)
        elif args.command=="fetch-public": result=fetch_public(args.manifest,args.out)
        elif args.command=="siem":
            events, provenance=load_events(args.input)
            write_json(args.out,payload(events,args.target))
            result={"status":"payload-only","events":len(events),"path":str(args.out),"input_sha256":provenance["sha256"]}
            if args.send:
                if not args.endpoint: raise ValueError("--send requires --endpoint")
                result=send(events,args.target,args.endpoint,args.token_env)
        else:
            rules=load_rules()
            if args.command=="validate": result={"valid_rules":len(rules),"event_rules":sum("detection" in r for r in rules),"correlations":sum("correlation" in r for r in rules),"pySigma_parsed":True}
            elif args.command=="translate": result={"generated":translate(rules,args.out)}
            elif args.command=="report": result=build_report(rules,args.attack,args.benign,args.out)
            elif args.command=="replay":
                events, provenance=load_events(args.input);alerts=replay(rules,events)
                result={"input":provenance,"events":len(events),"alerts":alerts,"native_siem_execution":False};write_json(args.out,result)
        print(json.dumps(result,indent=2));return 0
    except Exception as exc:
        # Avoid tracebacks with request headers or environment secrets in routine CLI output.
        print(f"adlab: {type(exc).__name__}: {exc}",file=sys.stderr);return 2

if __name__=="__main__": sys.exit(main())
