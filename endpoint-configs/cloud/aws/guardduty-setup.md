# AWS GuardDuty → SOC Lab Integration

## Overview
Forward GuardDuty findings to OpenSearch via EventBridge → Lambda → OpenSearch.

## Quick Setup (5 steps)

### Step 1 — Enable GuardDuty
```bash
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES
```

### Step 2 — Create EventBridge Rule
```bash
aws events put-rule \
  --name "GuardDuty-to-SOC" \
  --event-pattern '{"source":["aws.guardduty"],"detail-type":["GuardDuty Finding"]}' \
  --state ENABLED
```

### Step 3 — Lambda forwarder (paste this code)
```python
import json, os, boto3, requests

OPENSEARCH = os.environ['OPENSEARCH_ENDPOINT']

def handler(event, context):
    finding = event['detail']
    doc = {
        "@timestamp": finding['updatedAt'],
        "log_source": "aws_guardduty",
        "sensor_type": "cloud",
        "cloud_provider": "aws",
        "severity": finding['severity'],
        "title": finding['title'],
        "type": finding['type'],
        "src_ip": finding.get('service', {}).get('action', {})
                        .get('networkConnectionAction', {})
                        .get('remoteIpDetails', {}).get('ipAddressV4', ''),
        "mitre_technique": "T1078" if "Recon" in finding['type'] else "",
        "message": finding['description'],
    }
    requests.post(f"{OPENSEARCH}/soc-logs-aws-guardduty/_doc",
                  json=doc, auth=('admin', os.environ['OPENSEARCH_PASSWORD']))
```

### Step 4 — Set Lambda env vars
- `OPENSEARCH_ENDPOINT` = http://your-soc-ip:9200
- `OPENSEARCH_PASSWORD`  = your password

### Step 5 — Test
```bash
aws guardduty create-sample-findings --detector-id YOUR_DETECTOR_ID \
  --finding-types "Recon:EC2/PortScan"
```
Check OpenSearch: `soc-logs-aws-guardduty-*`
