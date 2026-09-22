# CloudTrail triage

Generated: 2026-09-22 22:26:37Z

## Summary

| | |
|---|---|
| Events loaded | 81 |
| Events analyzed | 81 |
| Activity window | 2026-03-14 02:11:42Z -> 2026-03-14 10:13:52Z |
| Duration | 8:02:10 |
| Unique IPs | 4 |
| Regions | 5 |
| Services | 13 |
| Principals | 2 |
| Permission denials | 40 (49%) |
| Successful mutating calls | 32 |
| Peak activity | 2026-03-14 02:15, 24 events/min |

## Findings

### [CRITICAL] Key created mid-incident has already been used

- Events: **14** (13 succeeded, 1 denied)
- Period: 2026-03-14T10:05:14Z -> 2026-03-14T10:13:15Z
- Calls: `GetServiceQuota` x3, `RequestServiceQuotaIncrease` x3, `AuthorizeSecurityGroupIngress` x3, `RunInstances` x3, `VerifyEmailIdentity` x1, `SendEmail` x1
- Regions: eu-west-1(4), ap-southeast-1(4), us-west-2(4), us-east-1(2)
- IPs: 198.51.100.77(14)
- Why it matters: The attacker switched to their own key. Revoking the original key achieves nothing.

```
2026-03-14T10:05:14Z  eu-west-1      GetServiceQuota                198.51.100.77    [ok] 
2026-03-14T10:05:51Z  eu-west-1      RequestServiceQuotaIncrease    198.51.100.77    [ok] 
2026-03-14T10:06:28Z  eu-west-1      AuthorizeSecurityGroupIngress  198.51.100.77    [ok] CIDR=ANY sg=sg-0example
2026-03-14T10:07:05Z  eu-west-1      RunInstances                   198.51.100.77    [ok] type=g5.12xlarge maxCount=8 minCount=1 launched=8
2026-03-14T10:07:42Z  ap-southeast-1 GetServiceQuota                198.51.100.77    [ok] 
2026-03-14T10:08:19Z  ap-southeast-1 RequestServiceQuotaIncrease    198.51.100.77    [ok] 
2026-03-14T10:08:56Z  ap-southeast-1 AuthorizeSecurityGroupIngress  198.51.100.77    [ok] CIDR=ANY sg=sg-0example
2026-03-14T10:09:33Z  ap-southeast-1 RunInstances                   198.51.100.77    [ok] type=g5.12xlarge maxCount=8 minCount=1 launched=8
```

### [CRITICAL] IAM persistence in the account

- Events: **3** (3 succeeded, 0 denied)
- Period: 2026-03-14T08:02:46Z -> 2026-03-14T08:04:00Z
- Calls: `CreateUser` x1, `AttachUserPolicy` x1, `CreateAccessKey` x1
- Regions: us-east-1(3)
- IPs: 198.51.100.23(3)
- Why it matters: Independent access that survives revoking the original key. Until it is cleaned up, the account is compromised.

```
2026-03-14T08:02:46Z  us-east-1      CreateUser                     198.51.100.23    [ok] user=support-svc
2026-03-14T08:03:23Z  us-east-1      AttachUserPolicy               198.51.100.23    [ok] user=support-svc policy=AdministratorAccess
2026-03-14T08:04:00Z  us-east-1      CreateAccessKey                198.51.100.23    [ok] user=support-svc newkey=AKIAI44QH8DHBEXAMPLE
```

### [CRITICAL] Anti-forensics (logging/detection tampering)

- Events: **1** (0 succeeded, 1 denied)
- Period: 2026-03-14T08:04:37Z -> 2026-03-14T08:04:37Z
- Calls: `StopLogging` x1
- Regions: us-east-1(1)
- IPs: 198.51.100.23(1)
- Why it matters: Deliberate covering of tracks. Anything that happened after this may not have been logged.

```
2026-03-14T08:04:37Z  us-east-1      StopLogging                    198.51.100.23    [AccessDenied] 
```

### [CRITICAL] Access to secrets and credentials

- Events: **1** (0 succeeded, 1 denied)
- Period: 2026-03-14T02:14:47Z -> 2026-03-14T02:14:47Z
- Calls: `GetSecretValue` x1
- Regions: us-east-1(1)
- IPs: 203.0.113.10(1)
- Why it matters: If these succeeded, the compromise extends beyond AWS. Treat everything stored there as leaked.

```
2026-03-14T02:14:47Z  us-east-1      GetSecretValue                 203.0.113.10     [AccessDeniedException] prod/db
```

### [HIGH] Bedrock / ML abuse (LLMjacking)

- Events: **25** (21 succeeded, 4 denied)
- Period: 2026-03-14T07:16:24Z -> 2026-03-14T07:22:09Z
- Calls: `InvokeModel` x18, `InvokeModelWithResponseStream` x4, `ListFoundationModels` x1, `GetFoundationModelAvailability` x1, `PutUseCaseForModelAccess` x1
- Regions: us-east-1(19), us-west-2(6)
- IPs: 198.51.100.23(25)
- Why it matters: Resale of model access. The bill grows fast and quietly, and no resources show up in the console.

```
2026-03-14T07:16:24Z  us-east-1      ListFoundationModels           198.51.100.23    [ok] 
2026-03-14T07:17:01Z  us-east-1      GetFoundationModelAvailability 198.51.100.23    [ok] 
2026-03-14T07:17:38Z  us-east-1      PutUseCaseForModelAccess       198.51.100.23    [ok] 
2026-03-14T07:18:37Z  us-east-1      InvokeModel                    198.51.100.23    [ok] model=anthropic.claude-3-haiku-20240307-v1:0
2026-03-14T07:18:48Z  us-east-1      InvokeModel                    198.51.100.23    [ok] model=anthropic.claude-3-5-sonnet-20240620-v1:0
2026-03-14T07:18:59Z  us-west-2      InvokeModel                    198.51.100.23    [ok] model=anthropic.claude-3-haiku-20240307-v1:0
2026-03-14T07:19:10Z  us-east-1      InvokeModel                    198.51.100.23    [ok] model=anthropic.claude-3-5-sonnet-20240620-v1:0
2026-03-14T07:19:32Z  us-west-2      InvokeModel                    198.51.100.23    [ok] model=anthropic.claude-3-5-sonnet-20240620-v1:0
```

### [HIGH] Compute launches (cryptomining)

- Events: **3** (3 succeeded, 0 denied)
- Period: 2026-03-14T10:07:05Z -> 2026-03-14T10:12:01Z
- Calls: `RunInstances` x3
- Regions: eu-west-1(1), ap-southeast-1(1), us-west-2(1)
- IPs: 198.51.100.77(3)
- Why it matters: The main driver of the bill. Check instance types and regions in the detail column.

```
2026-03-14T10:07:05Z  eu-west-1      RunInstances                   198.51.100.77    [ok] type=g5.12xlarge maxCount=8 minCount=1 launched=8
2026-03-14T10:09:33Z  ap-southeast-1 RunInstances                   198.51.100.77    [ok] type=g5.12xlarge maxCount=8 minCount=1 launched=8
2026-03-14T10:12:01Z  us-west-2      RunInstances                   198.51.100.77    [ok] type=g5.12xlarge maxCount=8 minCount=1 launched=8
```

### [HIGH] Mail/messaging abuse (SES/SNS)

- Events: **2** (1 succeeded, 1 denied)
- Period: 2026-03-14T10:12:38Z -> 2026-03-14T10:13:15Z
- Calls: `VerifyEmailIdentity` x1, `SendEmail` x1
- Regions: us-east-1(2)
- IPs: 198.51.100.77(2)
- Why it matters: Spam/phishing sent in the company's name. Beyond the money, this hurts domain reputation and can get it blocklisted.

```
2026-03-14T10:12:38Z  us-east-1      VerifyEmailIdentity            198.51.100.77    [ok] billing@example.com
```

### [HIGH] Web console sign-in

- Events: **1** (0 succeeded, 1 denied)
- Period: 2026-03-14T10:13:52Z -> 2026-03-14T10:13:52Z
- Calls: `ConsoleLogin` x1
- Regions: us-east-1(1)
- IPs: 192.0.2.55(1)
- Why it matters: If the sign-in succeeded, the attacker had a password or a federation token, not just an API key.

```
2026-03-14T10:13:52Z  us-east-1      ConsoleLogin                   192.0.2.55       [Failed authentication] result=Failure mfa=No
```

### [HIGH] Bedrock calls

- Events: **1** (1 succeeded, 0 denied)
- Period: 2026-03-14T07:18:15Z -> 2026-03-14T07:18:15Z
- Calls: `GetModelInvocationLoggingConfiguration` x1
- Regions: us-east-1(1)
- IPs: 198.51.100.23(1)
- Why it matters: Any Bedrock activity on a compromised key is abuse until proven otherwise.

```
2026-03-14T07:18:15Z  us-east-1      GetModelInvocationLoggingConfiguration 198.51.100.23    [ok] 
```

### [MEDIUM] Activity spread across 5 regions

- Events: **81** (0 succeeded, 0 denied)
- Regions: us-east-1(39), us-west-2(16), eu-west-1(10), ap-southeast-1(10), eu-central-1(6)
- Why it matters: Fanning out across regions is a signature of automated abuse. A region-restricting SCP cuts it off.

### [MEDIUM] Mass permission denials (permission brute-forcing)

- Events: **40** (0 succeeded, 40 denied)
- Period: 2026-03-14T02:13:33Z -> 2026-03-14T10:13:52Z
- Calls: `DescribeInstances` x5, `ListFunctions20150331` x5, `DescribeDBInstances` x5, `ListClusters` x5, `DescribeTrails` x5, `GetSendQuota` x5, `InvokeModel` x4, `GetAccountAuthorizationDetails` x1, `ListSecrets` x1, `GetSecretValue` x1
- Regions: us-east-1(14), us-west-2(8), eu-west-1(6), eu-central-1(6), ap-southeast-1(6)
- IPs: 203.0.113.10(33), 198.51.100.23(5), 198.51.100.77(1), 192.0.2.55(1)
- Why it matters: Looks like automated probing of available APIs. The attempted calls show what they were after.

```
2026-03-14T02:13:33Z  us-east-1      GetAccountAuthorizationDetails 203.0.113.10     [AccessDenied] 
2026-03-14T02:14:10Z  us-east-1      ListSecrets                    203.0.113.10     [AccessDeniedException] 
2026-03-14T02:14:47Z  us-east-1      GetSecretValue                 203.0.113.10     [AccessDeniedException] prod/db
2026-03-14T02:14:49Z  us-east-1      DescribeInstances              203.0.113.10     [AccessDenied] 
2026-03-14T02:14:51Z  us-east-1      ListFunctions20150331          203.0.113.10     [AccessDenied] 
2026-03-14T02:14:53Z  us-east-1      DescribeDBInstances            203.0.113.10     [AccessDenied] 
2026-03-14T02:14:55Z  us-east-1      ListClusters                   203.0.113.10     [AccessDenied] 
2026-03-14T02:14:57Z  us-east-1      DescribeTrails                 203.0.113.10     [AccessDenied] 
```

### [MEDIUM] Non-interactive clients (scripts, not console/CLI)

- Events: **36** (3 succeeded, 33 denied)
- Period: 2026-03-14T02:11:42Z -> 2026-03-14T02:15:47Z
- Calls: `DescribeInstances` x5, `ListFunctions20150331` x5, `DescribeDBInstances` x5, `ListClusters` x5, `DescribeTrails` x5, `GetSendQuota` x5, `GetCallerIdentity` x1, `ListBuckets` x1, `ListUsers` x1, `GetAccountAuthorizationDetails` x1
- Regions: us-east-1(12), us-west-2(6), eu-west-1(6), eu-central-1(6), ap-southeast-1(6)
- IPs: 203.0.113.10(36)
- Why it matters: This User-Agent does not come from normal work by the company's people or services.

```
2026-03-14T02:11:42Z  us-east-1      GetCallerIdentity              203.0.113.10     [ok] 
2026-03-14T02:12:19Z  us-east-1      ListBuckets                    203.0.113.10     [ok] 
2026-03-14T02:12:56Z  us-east-1      ListUsers                      203.0.113.10     [ok] 
```

### [MEDIUM] Quota increase requests

- Events: **6** (6 succeeded, 0 denied)
- Period: 2026-03-14T10:05:14Z -> 2026-03-14T10:10:47Z
- Calls: `GetServiceQuota` x3, `RequestServiceQuotaIncrease` x3
- Regions: eu-west-1(2), ap-southeast-1(2), us-west-2(2)
- IPs: 198.51.100.77(6)
- Why it matters: Asking for higher limits means they hit the ceiling and wanted to burn more.

```
2026-03-14T10:05:14Z  eu-west-1      GetServiceQuota                198.51.100.77    [ok] 
2026-03-14T10:05:51Z  eu-west-1      RequestServiceQuotaIncrease    198.51.100.77    [ok] 
2026-03-14T10:07:42Z  ap-southeast-1 GetServiceQuota                198.51.100.77    [ok] 
2026-03-14T10:08:19Z  ap-southeast-1 RequestServiceQuotaIncrease    198.51.100.77    [ok] 
2026-03-14T10:10:10Z  us-west-2      GetServiceQuota                198.51.100.77    [ok] 
2026-03-14T10:10:47Z  us-west-2      RequestServiceQuotaIncrease    198.51.100.77    [ok] 
```

### [MEDIUM] Network and access changes

- Events: **3** (3 succeeded, 0 denied)
- Period: 2026-03-14T10:06:28Z -> 2026-03-14T10:11:24Z
- Calls: `AuthorizeSecurityGroupIngress` x3
- Regions: eu-west-1(1), ap-southeast-1(1), us-west-2(1)
- IPs: 198.51.100.77(3)
- Why it matters: Look for 0.0.0.0/0 and for peering into foreign VPCs.

```
2026-03-14T10:06:28Z  eu-west-1      AuthorizeSecurityGroupIngress  198.51.100.77    [ok] CIDR=ANY sg=sg-0example
2026-03-14T10:08:56Z  ap-southeast-1 AuthorizeSecurityGroupIngress  198.51.100.77    [ok] CIDR=ANY sg=sg-0example
2026-03-14T10:11:24Z  us-west-2      AuthorizeSecurityGroupIngress  198.51.100.77    [ok] CIDR=ANY sg=sg-0example
```

### [LOW] Environment reconnaissance

- Events: **10** (3 succeeded, 7 denied)
- Period: 2026-03-14T02:11:42Z -> 2026-03-14T02:15:45Z
- Calls: `DescribeTrails` x5, `GetCallerIdentity` x1, `ListBuckets` x1, `ListUsers` x1, `GetAccountAuthorizationDetails` x1, `ListSecrets` x1
- Regions: us-east-1(6), us-west-2(1), eu-west-1(1), eu-central-1(1), ap-southeast-1(1)
- IPs: 203.0.113.10(10)
- Why it matters: Initial reconnaissance. Its makeup identifies the tool, and its timing establishes T0.

```
2026-03-14T02:11:42Z  us-east-1      GetCallerIdentity              203.0.113.10     [ok] 
2026-03-14T02:12:19Z  us-east-1      ListBuckets                    203.0.113.10     [ok] 
2026-03-14T02:12:56Z  us-east-1      ListUsers                      203.0.113.10     [ok] 
```

## Sources (IP)

| IP | Events | Denied | Successful changes | First seen | Last seen | Regions | User-Agent |
|---|---|---|---|---|---|---|---|
| `203.0.113.10` | 36 | 33 | 0 | 2026-03-14 02:11:42Z | 2026-03-14 02:15:47Z | 5 | Go-http-client/1.1 |
| `198.51.100.23` | 30 | 5 | 22 | 2026-03-14 07:16:24Z | 2026-03-14 08:04:37Z | 2 | aws-sdk-go-v2/1.30.3 os/linux lang/go#1.22.5 |
| `198.51.100.77` | 14 | 1 | 10 | 2026-03-14 10:05:14Z | 2026-03-14 10:13:15Z | 4 | Boto3/1.34.100 md/Botocore#1.34.100 ua/2.0 os |
| `192.0.2.55` | 1 | 1 | 0 | 2026-03-14 10:13:52Z | 2026-03-14 10:13:52Z | 1 | Mozilla/5.0 (Windows NT 10.0; Win64; x64) |

IPs need external enrichment (ASN, geo, reputation) - this script makes no network calls. Ready-made list: `iocs_ip.txt`.

## Activity sessions (gap > 30 min)

| # | Start | End | Events | Denied | IPs | Regions | Top calls |
|---|---|---|---|---|---|---|---|
| 1 | 2026-03-14 02:11:42Z | 2026-03-14 02:15:47Z | 36 | 33 | 203.0.113.10 | 5 | DescribeInstances x5, ListFunctions20150331 x5, DescribeDBInstances x5, ListClusters x5 |
| 2 | 2026-03-14 07:16:24Z | 2026-03-14 07:22:09Z | 26 | 4 | 198.51.100.23 | 2 | InvokeModel x18, InvokeModelWithResponseStream x4, ListFoundationModels x1, GetFoundationModelAvailability x1 |
| 3 | 2026-03-14 08:02:46Z | 2026-03-14 08:04:37Z | 4 | 1 | 198.51.100.23 | 1 | CreateUser x1, AttachUserPolicy x1, CreateAccessKey x1, StopLogging x1 |
| 4 | 2026-03-14 10:05:14Z | 2026-03-14 10:13:52Z | 15 | 2 | 198.51.100.77, 192.0.2.55 | 4 | GetServiceQuota x3, RequestServiceQuotaIncrease x3, AuthorizeSecurityGroupIngress x3, RunInstances x3 |

## Actual blast radius

Successful mutating calls - this is what the attacker actually did:

- `InvokeModel` x14
- `InvokeModelWithResponseStream` x4
- `RequestServiceQuotaIncrease` x3
- `AuthorizeSecurityGroupIngress` x3
- `RunInstances` x3
- `PutUseCaseForModelAccess` x1
- `CreateUser` x1
- `AttachUserPolicy` x1
- `CreateAccessKey` x1
- `VerifyEmailIdentity` x1

Mutating calls that were **denied** - this is what they tried but could not do:

- `InvokeModel` x4
- `StopLogging` x1
- `SendEmail` x1
- `ConsoleLogin` x1

## Top calls

- `bedrock:InvokeModel` x18
- `ec2:DescribeInstances` x5
- `lambda:ListFunctions20150331` x5
- `rds:DescribeDBInstances` x5
- `ecs:ListClusters` x5
- `cloudtrail:DescribeTrails` x5
- `ses:GetSendQuota` x5
- `bedrock:InvokeModelWithResponseStream` x4
- `servicequotas:GetServiceQuota` x3
- `servicequotas:RequestServiceQuotaIncrease` x3
- `ec2:AuthorizeSecurityGroupIngress` x3
- `ec2:RunInstances` x3
- `sts:GetCallerIdentity` x1
- `s3:ListBuckets` x1
- `iam:ListUsers` x1
- `iam:GetAccountAuthorizationDetails` x1
- `secretsmanager:ListSecrets` x1
- `secretsmanager:GetSecretValue` x1
- `bedrock:ListFoundationModels` x1
- `bedrock:GetFoundationModelAvailability` x1
- `bedrock:PutUseCaseForModelAccess` x1
- `bedrock:GetModelInvocationLoggingConfiguration` x1
- `iam:CreateUser` x1
- `iam:AttachUserPolicy` x1
- `iam:CreateAccessKey` x1
- `cloudtrail:StopLogging` x1
- `ses:VerifyEmailIdentity` x1
- `ses:SendEmail` x1
- `signin:ConsoleLogin` x1

## Limitations of this analysis

- Management events only. S3 object access, Lambda invocations and other data events are not recorded in Event History, so data access **can be neither confirmed nor ruled out**.
- Event History keeps 90 days. If T0 runs into the edge of that window, report the initial compromise date as "no later than" rather than as exact.
- Absence of an event does not mean absence of the action if the findings include StopLogging/DeleteTrail.
- No attribution by IP without external enrichment. VPS/cloud ASNs say nothing about the owner.
