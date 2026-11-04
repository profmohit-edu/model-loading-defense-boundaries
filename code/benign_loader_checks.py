"""Benign NumPy persistence checks. No malicious artifacts or unsafe custom callables.
Requires NumPy. Generated object arrays contain strings and integers only.
"""
from pathlib import Path
import tempfile,json,platform,sys
import numpy as np
B=Path(__file__).resolve().parents[1]
def check():
 rows=[]
 with tempfile.TemporaryDirectory() as temp:
  d=Path(temp)
  for fmt in ['npy','npz']:
   for dtype in ['numeric','object']:
    array=np.array([1,2,3],dtype=np.int64) if dtype=='numeric' else np.array(['alpha',7,None],dtype=object)
    p=d/f'{dtype}.{fmt}'
    if fmt=='npy':np.save(p,array)
    else:np.savez(p,values=array)
    for policy in ['default','false','true']:
     kw={} if policy=='default' else {'allow_pickle':policy=='true'}
     row={'case_id':f'C{len(rows)+1:02}','format':fmt,'array_kind':dtype,'policy':policy,'open_returned':False,'array_access_succeeded':False,'failure_stage':None,'exception':None}
     handle=None
     try:
      handle=np.load(p,**kw);row['open_returned']=True
      try:
       value=handle['values'] if fmt=='npz' else handle
       assert value.tolist()==array.tolist();row['array_access_succeeded']=True
      except ValueError as e:row['failure_stage']='array access';row['exception']=type(e).__name__
     except ValueError as e:row['failure_stage']='load call';row['exception']=type(e).__name__
     finally:
      if fmt=='npz' and handle is not None:handle.close()
     expected=dtype=='numeric' or policy=='true'
     assert row['array_access_succeeded']==expected,row
     if not expected:assert row['failure_stage']==('array access' if fmt=='npz' else 'load call'),row
     rows.append(row)
 out={'provenance':'Local benign policy probes, not an exploit test, scanner benchmark, or proof of loader security.','python':platform.python_version(),'numpy':np.__version__,'platform':sys.platform,'cases':rows,'summary':{'cases':len(rows),'accessible':sum(r['array_access_succeeded'] for r in rows),'blocked_at_load':sum(r['failure_stage']=='load call' for r in rows),'blocked_at_access':sum(r['failure_stage']=='array access' for r in rows)}}
 (B/'evidence').mkdir(exist_ok=True);(B/'evidence/benign_loader_results.json').write_text(json.dumps(out,indent=2));print(json.dumps(out['summary']|{'numpy':np.__version__,'python':platform.python_version()},indent=2))
if __name__=='__main__':check()
