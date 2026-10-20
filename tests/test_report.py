import json
from pathlib import Path
from adlab.engine import ROOT,load_rules
from adlab.report import build_report

def test_bundled_report_self_contained(tmp_path):
    r=build_report(load_rules(),ROOT/'fixtures/attack.jsonl',ROOT/'fixtures/benign.jsonl',tmp_path)
    assert r['input_origin']=='bundled-synthetic-verified-by-sha256'
    assert (tmp_path/'docs/rules/01_rdp_remote_logon.md').exists()
    assert (tmp_path/'rules/01_rdp_remote_logon.yml').exists()
    assert (tmp_path/'queries/kql/01_rdp_remote_logon.kql').exists()
    text=(tmp_path/'report.html').read_text();assert '../../docs' not in text
    assert '"synthetic": true' in text
    assert text.count('src:url(data:font/woff2;base64,') == 3
    assert '__FONT_CSS__' not in text
    assert (tmp_path/'assets/OFL-LICENSE.txt').read_bytes() == (ROOT/'adlab/assets/OFL-LICENSE.txt').read_bytes()
    manifest=json.loads((tmp_path/'assets/font-provenance.json').read_text())
    import hashlib
    for source in manifest['files']:
        assert hashlib.sha256((tmp_path/'assets'/source['path']).read_bytes()).hexdigest() == source['sha256']

def test_copied_bundled_data_retains_hash_provenance(tmp_path):
    p=tmp_path/'copy.jsonl';p.write_bytes((ROOT/'fixtures/attack.jsonl').read_bytes())
    r=build_report(load_rules(),p,ROOT/'fixtures/benign.jsonl',tmp_path/'out')
    assert r['input_origin']=='bundled-synthetic-verified-by-sha256'

def test_custom_input_never_assumed_real_or_synthetic_and_escapes_html(tmp_path):
    p=tmp_path/'capture.jsonl';record=json.loads((ROOT/'fixtures/attack.jsonl').read_text().splitlines()[0]);record['User']='</script><script>alert(1)</script>';p.write_text(json.dumps(record)+'\n')
    r=build_report(load_rules(),p,ROOT/'fixtures/benign.jsonl',tmp_path/'out')
    assert r['input_origin']=='operator-supplied-provenance-unverified'
    text=(tmp_path/'out/report.html').read_text();assert '"synthetic": false' in text
    assert '</script><script>alert(1)' not in text
    assert r['rules_triggered']==1

def test_same_record_id_in_two_sets_keeps_evidence_separate(tmp_path):
    a=json.loads((ROOT/'fixtures/attack.jsonl').read_text().splitlines()[0]);b={**a,'User':'benign-owner'}
    p=tmp_path/'positive.jsonl';p.write_text(json.dumps(a)+'\n');q=tmp_path/'benign.jsonl';q.write_text(json.dumps(b)+'\n')
    build_report(load_rules(),p,q,tmp_path/'out')
    text=(tmp_path/'out/report.html').read_text();payload=text.split('<script id="report-data" type="application/json">')[1].split('</script>')[0];data=json.loads(payload)
    assert data['events']['positive'][a['RecordId']]['User']!=data['events']['benign'][b['RecordId']]['User']
