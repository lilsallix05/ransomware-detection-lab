"""Regressions from independent integration review."""
import copy,json
from pathlib import Path
import pytest,yaml
from adlab.engine import ROOT,load_rules
from adlab.importers import normalize,load_events
from adlab.translate import translate

def event():return {'EventID':4769,'Provider':'Microsoft-Windows-Security-Auditing','Channel':'Security','Computer':'DC01','TimeCreated':'2026-10-20T00:00:00Z','EventRecordID':'1234'}

def test_native_identity_survives_overlapping_export():
 a=normalize(event(),1,'a'*64);b=normalize(event(),99,'b'*64)
 assert a['RecordId']==b['RecordId']
 assert normalize(dict(event(),Computer='DC02'))['RecordId']!=a['RecordId']
 assert normalize(dict(event(),TimeCreated='2026-10-21T00:00:00Z'))['RecordId']!=a['RecordId']

def test_duplicate_native_records_rejected(tmp_path):
 p=tmp_path/'overlap.jsonl';p.write_text((json.dumps(event())+'\n')*2)
 with pytest.raises(ValueError,match='Duplicate'):load_events(p)

@pytest.mark.parametrize('patch',[{'Computer':{}},{'Provider':['x']},{'Channel':1},{'EventID':True},{'EventID':-1},{'EventRecordID':'x'}])
def test_malformed_native_fields_rejected(patch):
 with pytest.raises(ValueError):normalize(dict(event(),**patch))

def test_truncated_xml_multiline_rejected(tmp_path):
 p=tmp_path/'truncated.xml';p.write_text('<Event><System/></Event>\n<Event\n xmlns="unfinished"')
 with pytest.raises(ValueError,match='Truncated'):load_events(p)

def test_translation_retains_hec_time_and_configured_threshold(tmp_path):
 rules=load_rules();rules[-1]['correlation']['condition']['gte']=23;translate(rules,tmp_path)
 spl=(tmp_path/'splunk/15_mass_file_burst.spl').read_text();kql=(tmp_path/'kql/15_mass_file_burst.kql').read_text()
 assert 'coalesce(_time,' in spl and '%:z' in spl
 assert '>= 23' in spl and '>= 23' in kql

def test_unsupported_correlation_group_rejected(tmp_path):
 for p in (ROOT/'rules').glob('*.yml'):(tmp_path/p.name).write_text(p.read_text())
 p=tmp_path/'15_mass_file_burst.yml';r=yaml.safe_load(p.read_text());r['correlation']['group-by']=['Computer'];p.write_text(yaml.safe_dump(r))
 with pytest.raises(ValueError,match='Unsupported correlation'):load_rules(tmp_path)

from adlab.integrations import send

def test_batch_failure_reports_partial_acceptance_without_secret(monkeypatch):
 import requests
 monkeypatch.setenv('ADLAB_REVIEW_TOKEN','test-secret-not-for-output')
 calls=[]
 class Accepted:
  status_code=200
  def raise_for_status(self):pass
  def json(self):return {'code':0}
 def post(*args,**kwargs):
  calls.append(kwargs)
  if len(calls)==2:raise requests.Timeout('test-secret-not-for-output')
  return Accepted()
 monkeypatch.setattr('adlab.integrations.requests.post',post)
 events=[normalize(dict(event(),EventRecordID=str(i))) for i in range(101)]
 with pytest.raises(ValueError) as failure:send(events,'splunk','https://localhost:8088/services/collector/event','ADLAB_REVIEW_TOKEN')
 assert '100 accepted event(s)' in str(failure.value)
 assert 'test-secret' not in str(failure.value)
 assert len(calls)==2 and len(calls[0]['data'].splitlines())==100

def test_sentinel_body_is_json_array_and_redirect_is_failure(monkeypatch):
 monkeypatch.setenv('ADLAB_REVIEW_TOKEN','test')
 calls=[]
 class Redirect:
  status_code=302
  def raise_for_status(self):pass
 def post(*args,**kwargs):calls.append(kwargs);return Redirect()
 monkeypatch.setattr('adlab.integrations.requests.post',post)
 with pytest.raises(ValueError,match='status 302'):send([normalize(event())],'sentinel','https://example.test/dataCollectionRules/dcr/streams/Custom-SelbiADLab?api-version=2023-01-01','ADLAB_REVIEW_TOKEN')
 body=json.loads(calls[0]['data']);assert body[0]['TimeGenerated']==event()['TimeCreated'];assert calls[0]['allow_redirects'] is False

def test_oversized_record_fails_before_any_send(monkeypatch):
 monkeypatch.setenv('ADLAB_REVIEW_TOKEN','test');calls=[]
 monkeypatch.setattr('adlab.integrations.requests.post',lambda *a,**k:calls.append(k))
 with pytest.raises(ValueError,match='no batches sent'):send([dict(normalize(event()),CommandLine='X'*(901*1024))],'splunk','https://example.test','ADLAB_REVIEW_TOKEN')
 assert calls==[]
