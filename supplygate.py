"""CycloneDX SBOM release policy checker."""
import argparse,json,sys
from pathlib import Path
def components(path):
 data=json.loads(Path(path).read_text(encoding='utf8'))
 if data.get('bomFormat')!='CycloneDX':raise ValueError('Expected CycloneDX JSON BOM')
 out={}
 for c in data.get('components',[]):
  key=c.get('purl') or f"{c.get('group','')}/{c.get('name','')}@{c.get('version','')}"
  if key.strip('/@'):out[key]=c
 return out
def evaluate(current,previous=None,policy=None):
 previous=previous or {};policy=policy or {};findings=[]
 blocked=set(policy.get('blocked_licenses',[]));banned=set(policy.get('blocked_packages',[]))
 for key,c in current.items():
  if key in banned or c.get('name') in banned:findings.append(dict(purl=key,rule='blocked-package'))
  licenses=[(x.get('license') or {}).get('id') or x.get('expression') for x in c.get('licenses',[]) if isinstance(x,dict)]
  if set(licenses)&blocked:findings.append(dict(purl=key,rule='blocked-license'))
  if policy.get('require_hash',False) and not c.get('hashes'):findings.append(dict(purl=key,rule='missing-hash'))
 return dict(added=sorted(current.keys()-previous.keys()),removed=sorted(previous.keys()-current.keys()),findings=findings,passed=not findings)
def main():
 p=argparse.ArgumentParser();p.add_argument('sbom');p.add_argument('--previous');p.add_argument('--policy');a=p.parse_args()
 try:r=evaluate(components(a.sbom),components(a.previous) if a.previous else {},json.loads(Path(a.policy).read_text()) if a.policy else {})
 except (ValueError,OSError) as e:print(str(e),file=sys.stderr);return 2
 print(json.dumps(r,indent=2));return 0 if r['passed'] else 1
if __name__=='__main__':sys.exit(main())
