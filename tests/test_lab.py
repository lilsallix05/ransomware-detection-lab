import copy
import json
from datetime import datetime,timedelta,timezone
from pathlib import Path
import pytest
from adlab.engine import ROOT, condition, field_match, load_rules, matches, replay
from adlab.importers import load_events,normalize,xml_event
from adlab.integrations import payload,fetch_public,send
from adlab.translate import translate

RULES=load_rules();RULE_MAP={r['id']:r for r in RULES}
ATTACK,_=load_events(ROOT/'fixtures/attack.jsonl');NEAR,_=load_events(ROOT/'fixtures/near-miss.jsonl')
CASES=json.loads((ROOT/'fixtures/cases.json').read_text())

@pytest.mark.parametrize('case',CASES,ids=lambda c:c['name'])
def test_every_rule_positive_and_negative(case):
    rid=case['rule_id'];events=[e for e in ATTACK if e['RecordId'] in case['positive']]
    assert any(a['rule_id']==rid for a in replay(RULES,events))
    negatives=[e for e in NEAR if e['RecordId'] in case['negative']]
    assert not any(a['rule_id']==rid for a in replay(RULES,negatives))

@pytest.mark.parametrize('case',CASES[:-1],ids=lambda c:c['name'])
def test_wrong_provider_and_required_field_missing(case):
    event=copy.deepcopy(next(e for e in ATTACK if e['RecordId']==case['positive'][0]));rule=RULE_MAP[case['rule_id']]
    wrong={**event,'Provider':'Fake-Provider'};assert not matches(rule,wrong)
    for name in rule['detection']['selection']:
        missing={k:v for k,v in event.items() if k!=name.split('|')[0]}
        assert not matches(rule,missing)

@pytest.mark.parametrize('expression',['selection or other','__import__("os")','selection.__class__','selection == True','1'])
def test_reject_unsupported_conditions(expression):
    with pytest.raises(ValueError):condition(expression,{'selection':True})

def test_modifiers_case_and_list_semantics():
    assert field_match({'A':'ABC def'},'A|contains|all',['abc','DEF'])
    assert not field_match({'A':'ABC def'},'A|contains|all',['abc','none'])
    assert field_match({'A':'ABC'},'A',['xyz','abc'])
    assert not field_match({},'A|contains','')
    with pytest.raises(ValueError):field_match({'A':'foo'},'A|re','foo')

def burst(n=20,spacing=2):
    exemplar=next(e for e in ATTACK if e['RecordId'].startswith('burst'))
    base=datetime(2026,10,19,1,5,45,tzinfo=timezone.utc)
    return [{**exemplar,'RecordId':f'e{i}','TimeCreated':(base+timedelta(seconds=i*spacing)).isoformat(),'TargetFilename':f'C:\\Lab\\{i}.locked'} for i in range(n)]
def correlations(events):return [a for a in replay(RULES,events) if a['slug']=='15_mass_file_burst']
def test_correlation_crosses_minute_and_sorts_input():
    a=correlations(burst());assert len(a)==1 and a[0]['distinct_files']==20
    assert correlations(list(reversed(burst())))==a

def test_correlation_boundary_and_below_threshold():
    assert not correlations(burst(19))
    assert correlations(burst(21,3))
    assert not correlations(burst(20,4))

def test_correlation_exact_60s_boundary():
    e=burst();e[-1]['TimeCreated']='2026-10-19T01:06:45+00:00';assert correlations(e)
    e[-1]['TimeCreated']='2026-10-19T01:06:45.001+00:00';assert not correlations(e)

def test_correlation_deduplicates_filenames_and_separates_hosts_and_images():
    e=burst(40)
    assert not correlations([{**x,'TargetFilename':'C:\\Lab\\same.locked'} for x in e])
    e=burst(20)
    assert not correlations([{**x,'Computer':f'WS{i%2}'} for i,x in enumerate(e)])
    assert not correlations([{**x,'Image':f'C:\\process{i%2}.exe'} for i,x in enumerate(e)])
    assert not correlations([{k:v for k,v in x.items() if k!='Image'} for x in e])

def test_correlation_rearms_after_expiry():
    first=burst();second=copy.deepcopy(first)
    for e in second:e['RecordId']+='later';e['TimeCreated']=(datetime.fromisoformat(e['TimeCreated'])+timedelta(minutes=3)).isoformat()
    assert len(correlations(first+second))==2

def test_known_benign_signals_are_visible():
    b,_=load_events(ROOT/'fixtures/benign.jsonl');a=replay(RULES,b)
    assert len(a)==4
    assert {x['slug'] for x in a}=={'01_rdp_remote_logon','04_rc4_service_ticket','05_psexec_service','07_shadow_copy_delete'}

def test_import_xml_and_splunk_json(tmp_path):
    xml="<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><Channel>Security</Channel><Computer>WS01</Computer><TimeCreated SystemTime='2026-01-01T00:00:00Z'/></System><EventData><Data Name='LogonType'>10</Data></EventData></Event>"
    p=tmp_path/'a.xml';p.write_text('<Events>'+xml+'</Events>');a,_=load_events(p)
    assert a[0]['LogonType']==10
    p=tmp_path/'splunk.jsonl';p.write_text(json.dumps({'result':{'_raw':xml}}));b,_=load_events(p)
    assert b[0]['EventID']==4624

def test_import_rejects_and_duplicate_ids(tmp_path):
    p=tmp_path/'a.jsonl';p.write_text(json.dumps(ATTACK[0])+'\nnot-json\n')
    with pytest.raises(ValueError,match='Rejected'):load_events(p)
    a,meta=load_events(p,allow_rejects=True);assert len(a)==1 and len(meta['rejected'])==1
    p.write_text((json.dumps(ATTACK[0])+'\n')*2)
    with pytest.raises(ValueError,match='Duplicate'):load_events(p)
    p.write_text('<Event broken>')
    with pytest.raises(ValueError):load_events(p)
    with pytest.raises(ValueError):xml_event('<!DOCTYPE Event [<!ENTITY x "bad">]><Event/>')

def test_timestamp_requires_timezone():
    with pytest.raises(ValueError):normalize({**ATTACK[0],'TimeCreated':'2026-01-01T00:00:00'})

def test_elastic_normalization():
    a=normalize({'@timestamp':'2026-01-01T00:00:00Z','winlog':{'event_id':1,'provider_name':'Microsoft-Windows-Sysmon','channel':'Microsoft-Windows-Sysmon/Operational','computer_name':'WS01','event_data':{'Image':'C:\\x.exe'}}})
    assert a['Image']=='C:\\x.exe'

def test_translate_all_rules(tmp_path):
    outputs=translate(RULES,tmp_path);assert len(outputs)==30
    for o in outputs:
        text=Path(o['path']).read_text();assert text.strip()
        if o['backend']=='kql':assert 'SelbiADLab_CL' in text
        else:assert 'index=adlab' in text
    assert 'time_window=60s' in (tmp_path/'splunk/15_mass_file_burst.spl').read_text()
    assert 'count_distinct' in (tmp_path/'kql/15_mass_file_burst.kql').read_text()

def test_payload_adapters_and_send_validation(monkeypatch):
    assert payload(ATTACK[:1],'splunk')[0]['event']['RecordId']==ATTACK[0]['RecordId']
    assert payload(ATTACK[:1],'sentinel')[0]['TimeGenerated']==ATTACK[0]['TimeCreated']
    with pytest.raises(ValueError):send(ATTACK,'splunk','http://example.com','ADLAB_TEST_MISSING')
    monkeypatch.delenv('ADLAB_TEST_MISSING',raising=False)
    with pytest.raises(ValueError,match='Missing token'):send(ATTACK,'splunk','https://example.com','ADLAB_TEST_MISSING')

def test_hec_failed_ack_does_not_claim_success(monkeypatch):
    class Fake:
        status_code=200
        def raise_for_status(self):pass
        def json(self):return {'code':4}
    monkeypatch.setenv('ADLAB_TEST_TOKEN','test-token')
    monkeypatch.setattr('adlab.integrations.requests.post',lambda *a,**k:Fake())
    with pytest.raises(ValueError,match='did not accept'):send(ATTACK,'splunk','https://localhost:8088/services/collector/event','ADLAB_TEST_TOKEN')

def test_public_digest_mismatch_does_not_write(tmp_path,monkeypatch):
    class Fake:
        status_code=200
        def raise_for_status(self):pass
        def iter_content(self,size):yield b'not dataset'
    monkeypatch.setattr('adlab.integrations.requests.get',lambda *a,**k:Fake())
    with pytest.raises(ValueError,match='SHA256'):fetch_public(ROOT/'fixtures/public-dataset.json',tmp_path/'out.xml')
    assert not (tmp_path/'out.xml').exists()

def test_unrecognized_rule_syntax_rejected(tmp_path):
    import yaml
    r=copy.deepcopy(RULES[0]);r['detection']['selection']['IpAddress|re']='probe';p=tmp_path/'test.yml';p.write_text(yaml.safe_dump(r))
    with pytest.raises(ValueError,match='Unsupported'):load_rules(tmp_path)
