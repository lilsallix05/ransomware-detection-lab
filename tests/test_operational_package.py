from pathlib import Path
import json
import uuid
import yaml
from adlab.engine import ROOT
from adlab.integrations import SENTINEL_FIELDS

def test_sentinel_contract_matches_adapter():
    table=json.loads((ROOT/'lab/sentinel/table.json').read_text());dcr=json.loads((ROOT/'lab/sentinel/dcr-template.json').read_text())
    columns=table['properties']['schema']['columns']
    assert {x['name'] for x in columns}==set(SENTINEL_FIELDS)|{'TimeGenerated'}
    assert dcr['kind']=='Direct'
    assert dcr['properties']['streamDeclarations']['Custom-SelbiADLab']['columns']==columns
    assert dcr['properties']['dataFlows'][0]['outputStream']=='Custom-SelbiADLab_CL'

def test_atomic_manifest_explicit_safe_local_test():
    d=yaml.safe_load((ROOT/'lab/atomic/T1486/T1486.yaml').read_text());a=d['atomic_tests'][0]
    assert len(d['atomic_tests'])==1
    uuid.UUID(a['auto_generated_guid'])
    assert a['auto_generated_guid'] in (ROOT/'docs/emulation.md').read_text()
    assert a['supported_platforms']==['windows']
    assert a['executor']['name']=='powershell'
    assert 'cleanup_command' not in a['executor']
    # Static contract checks only; this does not execute or parse PowerShell.
    assert 'LAB-ONLY' in a['executor']['command'] and '[guid]::NewGuid()' in a['executor']['command']

def test_metasploit_resource_is_metadata_only():
    commands=[x.strip() for x in (ROOT/'lab/metasploit/review-only.rc').read_text().splitlines() if x.strip() and not x.startswith('#')]
    assert commands==['version','search type:post platform:windows gather','exit -y']
