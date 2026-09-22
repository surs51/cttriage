# cttriage

Fast first-pass triage of AWS CloudTrail logs after account compromise.

Point it at CloudTrail JSON dumps and within seconds you get what the attacker tried, what
actually succeeded, which IPs and keys were involved, and a timeline you can hand to the rest of the
response team. It is a single Python file with no dependencies, and it never touches the network.

```
$ python3 cttriage.py examples/sample_events.json
  examples/sample_events.json                                 81

========================================================================
Events: 81 | window 2026-03-14 02:11:42Z -> 2026-03-14 10:13:52Z | IPs: 4 | regions: 5
========================================================================

IPs:
  203.0.113.10           36 events    33 denied    0 successful changes  Go-http-client/1.1
  198.51.100.23          30 events     5 denied   22 successful changes  aws-sdk-go-v2/1.30.3 os/linux lang/go#1.
  198.51.100.77          14 events     1 denied   10 successful changes  Boto3/1.34.100 md/Botocore#1.34.100 ua/2
  192.0.2.55              1 events     1 denied    0 successful changes  Mozilla/5.0 (Windows NT 10.0; Win64; x64

Findings:
  [CRITICAL] Key created mid-incident has already been used        14 events (ok 13)
  [CRITICAL] IAM persistence in the account                         3 events (ok 3)
  [CRITICAL] Anti-forensics (logging/detection tampering)           1 events (ok 0)
  [CRITICAL] Access to secrets and credentials                      1 events (ok 0)
  [HIGH    ] Bedrock / ML abuse (LLMjacking)                       25 events (ok 21)
  [HIGH    ] Compute launches (cryptomining)                        3 events (ok 3)
  ...
```

The full report for this run is in [triage_out/report.md](triage_out/report.md). The sample
incident is synthetic and uses only documentation IPs and AWS example account and key IDs.

## Requirements

Python 3.10 or newer. Standard library only, so there is nothing to install.

## Quick start

```bash
python3 cttriage.py events.json                 # report in English
python3 cttriage.py events.json -ru             # report in Russian
python3 cttriage.py dumps/ -o case-42           # a whole folder, custom output dir
python3 cttriage.py dumps/ --key AKIAIOSFODNN7EXAMPLE
```

Results are written to `triage_out/` unless you pass `-o`.

## Getting the logs

**Console:** CloudTrail > Event history > Download events → JSON.
Event history is per region, so repeat this for every region you use.

**CLI:** `lookup-events` returns one region at a time, so loop over all of them:

```bash
mkdir -p dumps
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws cloudtrail lookup-events --region "$r" \
    --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE \
    --output json > "dumps/events_$r.json"
done

python3 cttriage.py dumps/
```

Drop `--lookup-attributes` to pull everything. Log files from an S3 trail work as well.

Accepted input, in any mix of files and folders (folders are searched recursively):

| Shape | Source |
|---|---|
| `{"Records": [...]}` | Console download, S3 trail log files |
| `{"Events": [{"CloudTrailEvent": "..."}]}` | `aws cloudtrail lookup-events` |
| `[{...}, ...]` | Bare list of events |
| One event per line | JSON Lines |

Each of these can also be gzipped (`.gz`). Events that show up in several dumps are counted once.

## Options

| Option | Description |
|---|---|
| `-o DIR`, `--out DIR` | Output directory (default `triage_out`) |
| `--key AKIA...` | Analyze only events made with this access key ID |
| `--user NAME` | Analyze only this principal |
| `--gap MIN` | Idle minutes that split activity into separate sessions (default 30) |
| `--keep-aws-internal` | Keep calls that AWS services made on your behalf (dropped by default) |
| `-ru`, `--ru` | Write the report and console output in Russian (default: English) |
| `--version` | Print the version |

## Output

| File | Contents |
|---|---|
| `report.md` | Summary, findings with sample events, source IPs, activity sessions, blast radius, top calls, limitations |
| `timeline.csv` | Every event in time order with a short `detail` column (instance type, model, new key ID, bucket, and so on) |
| `findings.csv` | One row per finding: severity, counts, time range, regions, top IPs |
| `ips.csv` | Per source IP: volume, denials, successful changes, first/last seen, user agent |
| `identities.csv` | Per principal: keys used, IPs, first/last seen |
| `iocs_ip.txt` | Plain list of source IPs for enrichment or blocking |

The "blast radius" section separates successful write calls (what the attacker actually did) from
denied ones (what they tried and couldn't do). That is usually the first question you'll be asked.

## What it detects

| Severity | ID | Finding | Example calls |
|---|---|---|---|
| CRITICAL | `PERSIST` | IAM persistence | `CreateUser`, `CreateAccessKey`, `AttachUserPolicy`, `CreateLoginProfile` |
| CRITICAL | `ANTIFOREN` | Anti-forensics | `StopLogging`, `DeleteTrail`, `DeleteDetector`, `DeleteFlowLogs` |
| CRITICAL | `SHARE` | External access grants | `ModifySnapshotAttribute`, `PutBucketPolicy`, `PutKeyPolicy` |
| CRITICAL | `SECRETS` | Secrets and credentials access | `GetSecretValue`, `GetParameters`, `Decrypt`, `GetPasswordData` |
| CRITICAL | `DESTRUCT` | Destructive actions | `DeleteBucket`, `TerminateInstances`, `ScheduleKeyDeletion` |
| CRITICAL | `NEWKEY_USED` | A key created during the incident was then used | - |
| HIGH | `COMPUTE` | Compute launches (cryptomining) | `RunInstances`, `CreateFleet`, `RequestSpotInstances` |
| HIGH | `LLMJACK` | Bedrock / ML abuse (LLMjacking) | `InvokeModel`, `Converse`, `PutUseCaseForModelAccess`, plus any other Bedrock call |
| HIGH | `MAIL` | SES/SNS abuse | `SendEmail`, `VerifyEmailIdentity`, `Publish` |
| HIGH | `BACKDOOR` | Code and automation | `CreateFunction`, `UpdateFunctionCode`, `SendCommand`, `CreateStack` |
| HIGH | `SNAPSHOT` | Snapshot / image creation | `CreateSnapshot`, `CreateDBSnapshot`, `CopyImage` |
| HIGH | `CONSOLE` | Web console sign-in | `ConsoleLogin`, `GetSigninToken` |
| MEDIUM | `NETWORK` | Network and access changes | `AuthorizeSecurityGroupIngress`, `CreateVpcPeeringConnection` |
| MEDIUM | `QUOTA` | Quota increase requests | `RequestServiceQuotaIncrease` |
| MEDIUM | `ENUM` | Permission brute-forcing | 15+ denied calls making up over 25% of all events |
| MEDIUM | `AUTOMATION` | Scripted clients | User agents such as `python-requests`, `Go-http-client`, `curl` |
| MEDIUM | `FANOUT` | Activity spread across 5+ regions | - |
| LOW | `RECON` | Reconnaissance | `GetCallerIdentity`, `ListBuckets`, `GetAccountAuthorizationDetails` |

Every finding in the report explains why it matters and lists up to eight sample events. The full
rule list is at the top of [cttriage.py](cttriage.py), and all report text lives in its `MSG` table.

## Limitations

- Event history only holds **management events** from the last **90 days**. Data events such as S3
  object reads or Lambda invocations are not there, so data access can be neither confirmed nor ruled out.
- If the findings include `StopLogging` or `DeleteTrail`, a missing event is not proof that the action didn't happen.
- IPs are not enriched (ASN, geolocation, reputation). Feed `iocs_ip.txt` to your own tooling.
- The rules are a triage aid, not a verdict. "No findings" does not mean the account is clean.


