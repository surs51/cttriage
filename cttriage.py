#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cttriage.py - triage CloudTrail JSON dumps for a compromised-credential incident.

Stdlib only. Eats any of these shapes:
    {"Records": [ {...}, ... ]}                      # console download / S3 trail
    {"Events":  [ {"CloudTrailEvent": "<json str>"} ]}  # aws cloudtrail lookup-events
    [ {...}, ... ]                                   # bare list
    one JSON object per line                         # jsonl
plus .gz of any of the above.

usage:
    python3 cttriage.py events.json                  # report in English
    python3 cttriage.py events.json -ru              # report in Russian
    python3 cttriage.py dump_dir/ -o out
    python3 cttriage.py dump_dir/ --key AKIAIOSFODNN7EXAMPLE
    python3 cttriage.py events.json --user alice --gap 30
"""

__version__ = "1.0.0"

import argparse
import csv
import glob
import gzip
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# detection rules
# (id, severity, {eventNames}); title + why matters live in MSG under id / id.why
EVENT_RULES = [
    ("PERSIST", "CRITICAL", {
        "CreateUser", "CreateAccessKey", "CreateLoginProfile", "UpdateLoginProfile",
        "CreateRole", "UpdateAssumeRolePolicy", "AttachUserPolicy", "AttachRolePolicy",
        "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy", "PutGroupPolicy",
        "AddUserToGroup", "CreateServiceSpecificCredential", "CreateVirtualMFADevice",
        "DeactivateMFADevice", "EnableMFADevice", "UpdateUser", "CreateGroup",
        "CreateSAMLProvider", "CreateOpenIDConnectProvider", "UpdateAccessKey",
    }),

    ("ANTIFOREN", "CRITICAL", {
        "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors",
        "DeleteDetector", "UpdateDetector", "DisassociateFromMasterAccount",
        "DeleteFlowLogs", "DeleteLogGroup", "DeleteLogStream",
        "StopConfigurationRecorder", "DeleteConfigurationRecorder",
        "DeleteConfigRule", "LeaveOrganization", "DisableSecurityHub",
        "DeleteMembers", "UpdateIPSet", "CreateIPSet", "DeleteAlarms",
    }),

    ("SHARE", "CRITICAL", {
        "ModifySnapshotAttribute", "ModifyImageAttribute", "ModifyDBSnapshotAttribute",
        "ModifyDBClusterSnapshotAttribute", "PutBucketPolicy", "PutBucketAcl",
        "PutObjectAcl", "PutBucketPublicAccessBlock", "DeletePublicAccessBlock",
        "PutResourcePolicy", "PutKeyPolicy", "ShareDirectory", "CreateResourceShare",
        "AssociateResourceShare", "PutImageRecipePolicy", "ModifyVpcEndpointServicePermissions",
    }),

    ("SECRETS", "CRITICAL", {
        "GetSecretValue", "BatchGetSecretValue", "GetParameter", "GetParameters",
        "GetParametersByPath", "Decrypt", "GenerateDataKey", "GetPasswordData",
        "RetrieveEnvironmentInfo", "GetAuthorizationToken", "GetFederationToken",
        "GetSessionToken", "GetCredentialsForIdentity", "GetClusterCredentials",
    }),

    ("SNAPSHOT", "HIGH", {
        "CreateSnapshot", "CreateSnapshots", "CreateDBSnapshot", "CreateDBClusterSnapshot",
        "CreateImage", "CopySnapshot", "CopyImage", "CopyDBSnapshot",
        "ExportImage", "CreateStoreImageTask", "StartExportTask",
    }),

    ("COMPUTE", "HIGH", {
        "RunInstances", "CreateFleet", "RequestSpotInstances", "RequestSpotFleet",
        "StartInstances", "CreateAutoScalingGroup", "UpdateAutoScalingGroup",
        "CreateLaunchTemplate", "CreateCluster", "RunTask", "CreateService",
        "RegisterTaskDefinition", "SubmitJob", "CreateComputeEnvironment",
        "CreateNotebookInstance", "CreateTrainingJob", "CreateNodegroup",
        "CreateWorkspaces", "CreateEnvironmentEC2",
    }),

    ("LLMJACK", "HIGH", {
        "InvokeModel", "InvokeModelWithResponseStream", "Converse", "ConverseStream",
        "CreateModelInvocationJob", "PutFoundationModelEntitlement",
        "CreateFoundationModelAgreement", "PutUseCaseForModelAccess",
        "ListFoundationModels", "GetFoundationModelAvailability",
        "CreateModelCustomizationJob", "InvokeAgent", "InvokeEndpoint",
    }),

    ("MAIL", "HIGH", {
        "SendEmail", "SendRawEmail", "SendBulkEmail", "SendTemplatedEmail",
        "VerifyEmailIdentity", "VerifyDomainIdentity", "CreateEmailIdentity",
        "UpdateAccountSendingEnabled", "SetIdentityDkimEnabled",
        "CreateConfigurationSet", "Publish", "SetSMSAttributes", "SubscribeToTopic",
        "CreateTopic", "Subscribe",
    }),

    ("BACKDOOR", "HIGH", {
        "CreateFunction", "CreateFunction20150331", "UpdateFunctionCode",
        "UpdateFunctionConfiguration", "AddPermission", "CreateEventSourceMapping",
        "PutRule", "PutTargets", "CreateStack", "UpdateStack", "CreatePipeline",
        "CreateStateMachine", "SendCommand", "CreateDocument", "StartAutomationExecution",
        "CreateAssociation", "RegisterTaskWithMaintenanceWindow",
    }),

    ("NETWORK", "MEDIUM", {
        "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
        "CreateSecurityGroup", "RevokeSecurityGroupIngress", "CreateVpcPeeringConnection",
        "AcceptVpcPeeringConnection", "CreateInternetGateway", "CreateRoute",
        "CreateNatGateway", "CreateClientVpnEndpoint", "CreateVpnConnection",
        "CreateTransitGateway", "ModifyVpcEndpoint",
    }),

    ("QUOTA", "MEDIUM", {
        "RequestServiceQuotaIncrease", "GetServiceQuota", "ListServiceQuotas",
        "CreateCase", "RequestSpotInstances",
    }),

    ("DESTRUCT", "CRITICAL", {
        "DeleteBucket", "DeleteObject", "DeleteObjects", "DeleteDBInstance",
        "DeleteDBCluster", "TerminateInstances", "DeleteVolume", "DeleteSnapshot",
        "DeleteKeyPair", "ScheduleKeyDeletion", "DisableKey", "DeleteSecret",
        "DeleteFileSystem", "DeleteTable", "DeleteStack", "DeleteUser", "DeleteRole",
    }),

    ("RECON", "LOW", {
        "GetCallerIdentity", "ListBuckets", "ListUsers", "ListRoles", "ListGroups",
        "ListAccessKeys", "ListAttachedUserPolicies", "ListAttachedRolePolicies",
        "ListUserPolicies", "GetAccountSummary", "GetAccountAuthorizationDetails",
        "DescribeRegions", "DescribeAccountAttributes", "ListAccounts",
        "SimulatePrincipalPolicy", "GetUser", "ListInstanceProfiles",
        "DescribeOrganization", "ListSecrets", "DescribeTrails", "GetAccountPasswordPolicy",
    }),

    ("CONSOLE", "HIGH", {
        "ConsoleLogin", "GetSigninToken", "SwitchRole", "CheckMfa",
    }),
]

# (id, severity, text key in MSG, eventSource prefixes)
SOURCE_RULES = [
    ("LLMJACK", "HIGH", "LLMJACK_SRC", ("bedrock",)),
]

# Eng / ru 
MSG = {
    # finding - why matter
    "PERSIST": ("IAM persistence in the account",
                "Закрепление в аккаунте (IAM)"),
    "PERSIST.why": ("Independent access that survives revoking the original key. "
                    "Until it is cleaned up, the account is compromised.",
                    "Независимый доступ, переживающий отзыв исходного ключа. Пока не зачищено - аккаунт скомпрометирован."),
    "ANTIFOREN": ("Anti-forensics (logging/detection tampering)",
                  "Противодействие расследованию"),
    "ANTIFOREN.why": ("Deliberate covering of tracks. Anything that happened after this may not have been logged.",
                      "Целенаправленное сокрытие следов. Всё, что было после этого, могло не залогироваться."),
    "SHARE": ("External access grants (resource sharing)",
              "Выдача доступа наружу (шаринг ресурсов)"),
    "SHARE.why": ("The typical way to take data out without GetObject: share a snapshot/bucket "
                  "with your own account. Check this first.",
                  "Типовой способ вытащить данные без GetObject: расшарить снапшот/бакет на свой аккаунт. Проверять в первую очередь."),
    "SECRETS": ("Access to secrets and credentials",
                "Доступ к секретам и креденшлам"),
    "SECRETS.why": ("If these succeeded, the compromise extends beyond AWS. "
                    "Treat everything stored there as leaked.",
                    "Если отработало успешно - компрометация вышла за пределы AWS. Всё, что там лежало, считать утёкшим."),
    "SNAPSHOT": ("Snapshot / image creation",
                 "Создание снапшотов / образов"),
    "SNAPSHOT.why": ("Harmless on its own, but combined with external sharing this is exactly how data gets exfiltrated.",
                     "Само по себе не страшно, но в связке с шарингом наружу это и есть эксфильтрация данных."),
    "COMPUTE": ("Compute launches (cryptomining)",
                "Запуск вычислительных ресурсов (майнинг)"),
    "COMPUTE.why": ("The main driver of the bill. Check instance types and regions in the detail column.",
                    "Основной источник счёта. Смотреть типы инстансов и регионы в колонке detail."),
    "LLMJACK": ("Bedrock / ML abuse (LLMjacking)",
                "Злоупотребление Bedrock / ML (LLMjacking)"),
    "LLMJACK.why": ("Resale of model access. The bill grows fast and quietly, "
                    "and no resources show up in the console.",
                    "Перепродажа доступа к моделям. Счёт растёт быстро и незаметно, ресурсов в консоли при этом не видно."),
    "MAIL": ("Mail/messaging abuse (SES/SNS)",
             "Злоупотребление рассылкой (SES/SNS)"),
    "MAIL.why": ("Spam/phishing sent in the company's name. Beyond the money, this hurts "
                 "domain reputation and can get it blocklisted.",
                 "Спам/фишинг от имени компании. Помимо денег это репутация домена и возможные блэклисты."),
    "BACKDOOR": ("Code and automation (backdoor)",
                 "Код и автоматизация (бэкдор)"),
    "BACKDOOR.why": ("Code execution that survives instance cleanup. SendCommand/SSM also means access inside EC2.",
                     "Исполнение кода, переживающее зачистку инстансов. SendCommand/SSM - ещё и доступ внутрь EC2."),
    "NETWORK": ("Network and access changes",
                "Изменения сети и доступа"),
    "NETWORK.why": ("Look for 0.0.0.0/0 and for peering into foreign VPCs.",
                    "Смотреть на 0.0.0.0/0 и на пиринги в чужие VPC."),
    "QUOTA": ("Quota increase requests",
              "Запросы на повышение лимитов"),
    "QUOTA.why": ("Asking for higher limits means they hit the ceiling and wanted to burn more.",
                  "Просили поднять лимиты - значит упёрлись в потолок и хотели жечь больше."),
    "DESTRUCT": ("Destructive actions",
                 "Разрушающие действия"),
    "DESTRUCT.why": ("Deletion of data or resources. Separate the attacker's actions from your own cleanup.",
                     "Удаление данных или ресурсов. Отделить действия атакующего от зачистки своими силами."),
    "RECON": ("Environment reconnaissance",
              "Разведка окружения"),
    "RECON.why": ("Initial reconnaissance. Its makeup identifies the tool, and its timing establishes T0.",
                  "Первичная разведка. По её составу опознаётся инструмент и по времени определяется T0."),
    "CONSOLE": ("Web console sign-in",
                "Вход в веб-консоль"),
    "CONSOLE.why": ("If the sign-in succeeded, the attacker had a password or a federation token, not just an API key.",
                    "Если вход успешен - у атакующего был пароль или federation-токен, а не только API-ключ."),
    "LLMJACK_SRC": ("Bedrock calls",
                    "Обращения к Bedrock"),
    "LLMJACK_SRC.why": ("Any Bedrock activity on a compromised key is abuse until proven otherwise.",
                        "Любая активность Bedrock на скомпрометированном ключе считается злоупотреблением, пока не доказано обратное."),
    "ENUM": ("Mass permission denials (permission brute-forcing)",
             "Массовые отказы в правах (перебор прав)"),
    "ENUM.why": ("Looks like automated probing of available APIs. The attempted calls show what they were after.",
                 "Похоже на автоматический перебор доступных API. По составу попыток видно, что искали."),
    "AUTOMATION": ("Non-interactive clients (scripts, not console/CLI)",
                   "Неинтерактивные клиенты (скрипты, не консоль и не CLI)"),
    "AUTOMATION.why": ("This User-Agent does not come from normal work by the company's people or services.",
                       "Такой User-Agent не создаётся штатной работой людей или сервисов компании."),
    "FANOUT": ("Activity spread across %d regions",
               "Активность размазана по %d регионам"),
    "FANOUT.why": ("Fanning out across regions is a signature of automated abuse. A region-restricting SCP cuts it off.",
                   "Веерный обход регионов - подпись автоматизированного злоупотребления. SCP на регионы это отсекает."),
    "NEWKEY_USED": ("Key created mid-incident has already been used",
                    "Созданный в ходе инцидента ключ уже использовался"),
    "NEWKEY_USED.why": ("The attacker switched to their own key. Revoking the original key achieves nothing.",
                        "Атакующий перешёл на собственный ключ. Отзыв исходного ключа ничего не даёт."),

    # loading / errors
    "cant_read": ("  ! cannot read %s: %s",
                  "  ! не читается %s: %s"),
    "bad_lines": ("  ! %s: skipped unparseable lines: %d",
                  "  ! %s: пропущено нераспарсенных строк: %d"),
    "no_files": ("No input files found.",
                 "Файлы не найдены."),
    "no_events": ("No events found. Check the JSON format.",
                  "Событий не найдено. Проверь формат JSON."),
    "no_events_filtered": ("No events left after filtering.",
                           "После фильтров не осталось событий."),

    # report
    "title": ("# CloudTrail triage\n",
              "# Триаж CloudTrail\n"),
    "generated": ("Generated: %s\n",
                  "Сформировано: %s\n"),
    "h_summary": ("## Summary\n",
                  "## Сводка\n"),
    "s_loaded": ("Events loaded", "Событий загружено"),
    "s_analyzed": ("Events analyzed", "Событий в анализе"),
    "s_dupes": ("Duplicates dropped", "Отброшено дублей"),
    "s_window": ("Activity window", "Окно активности"),
    "s_duration": ("Duration", "Длительность"),
    "s_ips": ("Unique IPs", "Уникальных IP"),
    "s_regions": ("Regions", "Регионов"),
    "s_services": ("Services", "Сервисов"),
    "s_principals": ("Principals", "Principal'ов"),
    "s_denied": ("Permission denials", "Отказов по правам"),
    "s_ok_mut": ("Successful mutating calls", "Успешных изменяющих вызовов"),
    "s_peak": ("Peak activity", "Пик активности"),
    "s_peak_val": ("%s, %d events/min", "%s, %d соб./мин"),

    # findings
    "h_findings": ("## Findings\n",
                   "## Находки\n"),
    "no_findings": ("No rules fired. That does not mean everything is clean - review timeline.csv manually.\n",
                    "Правила не сработали. Это не значит, что всё чисто - проверь timeline.csv руками.\n"),
    "f_events": ("- Events: **%d** (%d succeeded, %d denied)",
                 "- Событий: **%d** (успешно %d, отказано %d)"),
    "f_period": ("- Period: %s -> %s",
                 "- Период: %s -> %s"),
    "f_calls": ("- Calls: %s",
                "- Вызовы: %s"),
    "f_regions": ("- Regions: %s",
                  "- Регионы: %s"),
    "f_ips": ("- IPs: %s",
              "- IP: %s"),
    "f_why": ("- Why it matters: %s",
              "- Почему важно: %s"),

    #IPs, sessions, blast radius, top calls
    "h_ips": ("## Sources (IP)\n",
              "## Источники (IP)\n"),
    "ips_header": ("| IP | Events | Denied | Successful changes | First seen | Last seen | Regions | User-Agent |",
                   "| IP | Событий | Отказов | Успешных изменений | Первое | Последнее | Регионов | User-Agent |"),
    "ips_note": ("IPs need external enrichment (ASN, geo, reputation) - this script makes no network calls. "
                 "Ready-made list: `iocs_ip.txt`.\n",
                 "IP нуждаются во внешнем обогащении (ASN, гео, репутация) - скрипт в сеть не ходит. "
                 "Готовый список: `iocs_ip.txt`.\n"),
    "h_sessions": ("## Activity sessions (gap > %d min)\n",
                   "## Сессии активности (разрыв > %d мин)\n"),
    "sess_header": ("| # | Start | End | Events | Denied | IPs | Regions | Top calls |",
                    "| # | Начало | Конец | Событий | Отказов | IP | Регионов | Основные вызовы |"),
    "h_blast": ("## Actual blast radius\n",
                "## Фактический blast radius\n"),
    "blast_ok": ("Successful mutating calls - this is what the attacker actually did:\n",
                 "Успешные изменяющие вызовы - это то, что атакующий реально сделал:\n"),
    "blast_ok_none": ("- no mutating calls recorded (read/recon only)",
                      "- изменяющих вызовов не зафиксировано (только чтение/разведка)"),
    "blast_denied": ("Mutating calls that were **denied** - this is what they tried but could not do:\n",
                     "Изменяющие вызовы, которые **не прошли** по правам - это то, что пытались, но не смогли:\n"),
    "blast_denied_none": ("- none",
                          "- таких нет"),
    "h_top": ("## Top calls\n",
              "## Топ вызовов\n"),

    # report: limitations
    "h_limits": ("## Limitations of this analysis\n",
                 "## Ограничения этого анализа\n"),
    "limit_data": ("Management events only. S3 object access, Lambda invocations and other data events "
                   "are not recorded in Event History, so data access **can be neither confirmed nor ruled out**.",
                   "Только management events. Обращения к объектам S3, вызовы Lambda и прочие data events "
                   "в Event History не пишутся, поэтому факт доступа к данным **нельзя ни подтвердить, ни опровергнуть**."),
    "limit_90d": ("Event History keeps 90 days. If T0 runs into the edge of that window, report the initial "
                  "compromise date as \"no later than\" rather than as exact.",
                  "Event History хранится 90 дней. Если T0 упирается в границу окна, дату первичной "
                  "компрометации указывать как \"не позднее\", а не как точную."),
    "limit_gaps": ("Absence of an event does not mean absence of the action if the findings include StopLogging/DeleteTrail.",
                   "Отсутствие события не равно отсутствию действия, если в находках есть StopLogging/DeleteTrail."),
    "limit_ip": ("No attribution by IP without external enrichment. VPS/cloud ASNs say nothing about the owner.",
                 "Атрибуция по IP без внешнего обогащения не делается. VPS/облачные ASN ничего не говорят о владельце."),

    # console summary
    "c_head": ("Events: %d | window %s -> %s | IPs: %d | regions: %d",
               "Событий: %d | окно %s -> %s | IP: %d | регионов: %d"),
    "c_ips": ("\nIPs:",
              "\nIP:"),
    "c_ip_row": ("  %-18s %6d events  %4d denied  %3d successful changes  %s",
                 "  %-18s %6d соб.  %4d отказов  %3d успешных изменений  %s"),
    "c_findings": ("\nFindings:",
                   "\nНаходки:"),
    "c_finding_row": ("  [%-8s] %-50s %5d events (ok %d)",
                      "  [%-8s] %-50s %5d соб. (ok %d)"),
    "c_written": ("\nWritten to %s/: report.md, timeline.csv, ips.csv, identities.csv, "
                  "findings.csv, iocs_ip.txt\n",
                  "\nЗаписано в %s/: report.md, timeline.csv, ips.csv, identities.csv, "
                  "findings.csv, iocs_ip.txt\n"),
}

LANG = 0 


def T(key, *args):
    """MSG[key] in the current language, %-formatted when args are given."""
    text = MSG[key][LANG]
    return text % args if args else text


AUTOMATION_UA = (
    "go-http-client", "python-requests", "python-urllib", "curl", "wget",
    "okhttp", "axios", "node-fetch", "java-sdk", "libwww", "httpx", "aiohttp",
    "postman", "insomnia",
)

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


#preload
def _open(path):
    if str(path).endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def _unwrap(obj):
    """Yield raw CloudTrail event dicts from whatever container we got."""
    if isinstance(obj, list):
        for item in obj:
            yield from _unwrap(item)
        return
    if not isinstance(obj, dict):
        return
    if "Records" in obj and isinstance(obj["Records"], list):
        for r in obj["Records"]:
            if isinstance(r, dict):
                yield r
        return
    if "Events" in obj and isinstance(obj["Events"], list):
        for e in obj["Events"]:
            raw = e.get("CloudTrailEvent") if isinstance(e, dict) else None
            if isinstance(raw, str):
                try:
                    yield json.loads(raw)
                    continue
                except json.JSONDecodeError:
                    pass
            if isinstance(e, dict):
                yield e
        return
    if "eventName" in obj or "eventID" in obj:
        yield obj


def load_file(path):
    try:
        with _open(path) as fh:
            text = fh.read()
    except OSError as exc:
        print(T("cant_read", path, exc), file=sys.stderr)
        return
    text = text.strip()
    if not text:
        return
    try:
        yield from _unwrap(json.loads(text))
        return
    except json.JSONDecodeError:
        pass
    bad = 0
    for line in text.splitlines():                      # jsonl fallback
        line = line.strip().rstrip(",")
        if not line or line in "[]":
            continue
        try:
            yield from _unwrap(json.loads(line))
        except json.JSONDecodeError:
            bad += 1
    if bad:
        print(T("bad_lines", path, bad), file=sys.stderr)


def collect_inputs(paths):
    out = []
    for p in paths:
        p = Path(p)
        if p.is_dir():
            for pat in ("*.json", "*.json.gz", "*.jsonl", "*.gz"):
                out.extend(sorted(p.rglob(pat)))
        elif p.exists():
            out.append(p)
        else:
            out.extend(Path(x) for x in sorted(glob.glob(str(p))))
    seen, uniq = set(), []
    for f in out:
        r = str(f.resolve())
        if r not in seen:
            seen.add(r)
            uniq.append(f)
    return uniq


# normalize
def dig(d, *path, default=None):
    cur = d
    for key in path:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(key)
        if cur is None:
            return default
    return cur


def parse_time(value):
    if not value:
        return None
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    txt = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(txt)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%b %d, %Y %I:%M:%S %p", "%Y-%m-%d %H:%M:%S"):
            try:
                dt = datetime.strptime(str(value), fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def identity_of(rec):
    ui = rec.get("userIdentity") or {}
    itype = ui.get("type") or "-"
    arn = ui.get("arn") or ""
    name = ui.get("userName")
    if not name:
        name = dig(ui, "sessionContext", "sessionIssuer", "userName")
    if not name and arn:
        parts = [p for p in arn.split("/") if p]
        if itype == "AssumedRole" and len(parts) >= 3:
            name = "%s/%s" % (parts[-2], parts[-1])
        else:
            name = parts[-1]
    if not name:
        name = ui.get("principalId") or ui.get("invokedBy") or "-"
    return itype, name, arn


def detail_of(rec):
    """Short human-readable 'what exactly' for the timeline."""
    name = rec.get("eventName") or ""
    rp = rec.get("requestParameters")
    re_ = rec.get("responseElements")
    rp = rp if isinstance(rp, dict) else {}
    re_ = re_ if isinstance(re_, dict) else {}
    bits = []

    if name == "RunInstances":
        itype = rp.get("instanceType") or dig(rp, "instancesSet", "items", default=None)
        if isinstance(itype, list) and itype:
            first = itype[0] if isinstance(itype[0], dict) else {}
            bits.append("type=%s" % first.get("instanceType", "?"))
        elif isinstance(itype, str):
            bits.append("type=%s" % itype)
        for k in ("maxCount", "minCount"):
            if rp.get(k):
                bits.append("%s=%s" % (k, rp[k]))
        items = dig(re_, "instancesSet", "items", default=[]) or []
        if isinstance(items, list) and items:
            bits.append("launched=%d" % len(items))
            t = items[0].get("instanceType") if isinstance(items[0], dict) else None
            if t and "type=" not in " ".join(bits):
                bits.append("type=%s" % t)
    elif name in ("InvokeModel", "InvokeModelWithResponseStream", "Converse", "ConverseStream"):
        model = rp.get("modelId") or rp.get("modelIdentifier")
        if not model:
            for res in rec.get("resources") or []:
                if isinstance(res, dict) and res.get("ARN"):
                    model = res["ARN"].split("/")[-1]
                    break
        bits.append("model=%s" % (model or "?"))
    elif name in ("CreateUser", "CreateAccessKey", "CreateLoginProfile", "DeleteUser",
                  "AttachUserPolicy", "PutUserPolicy", "AddUserToGroup", "UpdateAccessKey"):
        if rp.get("userName"):
            bits.append("user=%s" % rp["userName"])
        if rp.get("policyArn"):
            bits.append("policy=%s" % str(rp["policyArn"]).split("/")[-1])
        newkey = dig(re_, "accessKey", "accessKeyId")
        if newkey:
            bits.append("newkey=%s" % newkey)
    elif name in ("CreateRole", "UpdateAssumeRolePolicy", "AttachRolePolicy", "AssumeRole"):
        if rp.get("roleName"):
            bits.append("role=%s" % rp["roleName"])
        if rp.get("roleArn"):
            bits.append("role=%s" % rp["roleArn"])
        if rp.get("policyArn"):
            bits.append("policy=%s" % str(rp["policyArn"]).split("/")[-1])
        trust = rp.get("assumeRolePolicyDocument")
        if isinstance(trust, str) and "arn:aws:iam::" in trust:
            bits.append("trust-doc")
    elif name in ("AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"):
        blob = json.dumps(rp)
        if "0.0.0.0/0" in blob or "::/0" in blob:
            bits.append("CIDR=ANY")
        if rp.get("groupId"):
            bits.append("sg=%s" % rp["groupId"])
    elif name in ("ModifySnapshotAttribute", "ModifyImageAttribute",
                  "ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute"):
        blob = json.dumps(rp)
        if '"all"' in blob or "'all'" in blob:
            bits.append("PUBLIC")
        for token in ("userIds", "valuesToAdd", "attributeValueToAdd"):
            if token in rp:
                bits.append("%s=%s" % (token, json.dumps(rp[token])[:60]))
    elif name in ("GetSecretValue", "GetParameter", "GetParameters", "GetParametersByPath"):
        bits.append(str(rp.get("secretId") or rp.get("name") or rp.get("path") or "?")[:60])
    elif name in ("PutBucketPolicy", "PutBucketAcl", "DeletePublicAccessBlock",
                  "PutBucketPublicAccessBlock", "ListObjects", "GetObject", "PutObject"):
        if rp.get("bucketName"):
            bits.append("bucket=%s" % rp["bucketName"])
    elif name == "ConsoleLogin":
        bits.append("result=%s" % dig(re_, "ConsoleLogin", default="?"))
        mfa = dig(rec, "additionalEventData", "MFAUsed")
        if mfa:
            bits.append("mfa=%s" % mfa)
    elif name in ("SendEmail", "SendRawEmail", "VerifyEmailIdentity", "CreateEmailIdentity"):
        bits.append(str(rp.get("source") or rp.get("emailAddress")
                        or rp.get("emailIdentity") or "?")[:60])
    elif name == "CreateFunction" or name.startswith("UpdateFunction"):
        bits.append("fn=%s" % str(rp.get("functionName") or "?")[:60])

    if not bits:
        for res in rec.get("resources") or []:
            if isinstance(res, dict) and res.get("ARN"):
                bits.append(res["ARN"].split(":")[-1][:60])
                break
    return " ".join(bits)


def normalize(rec):
    itype, iname, iarn = identity_of(rec)
    src = (rec.get("eventSource") or "").replace(".amazonaws.com", "")
    ip = rec.get("sourceIPAddress") or "-"
    return {
        "dt": parse_time(rec.get("eventTime")),
        "time": rec.get("eventTime") or "",
        "region": rec.get("awsRegion") or "-",
        "service": src or "-",
        "event": rec.get("eventName") or "-",
        "itype": itype,
        "principal": iname,
        "arn": iarn,
        "key": dig(rec, "userIdentity", "accessKeyId") or "-",
        "ip": ip,
        "ua": rec.get("userAgent") or "-",
        "error": rec.get("errorCode") or "",
        "errmsg": (rec.get("errorMessage") or "")[:200],
        "readonly": rec.get("readOnly"),
        "detail": detail_of(rec),
        "event_id": rec.get("eventID") or "",
        "account": rec.get("recipientAccountId") or dig(rec, "userIdentity", "accountId") or "-",
        "mfa": dig(rec, "userIdentity", "sessionContext", "attributes", "mfaAuthenticated") or "",
        "aws_internal": ip.endswith(".amazonaws.com") or ip in ("AWS Internal", "AWS Internal Service"),
    }


def is_mutating(ev):
    if ev["readonly"] is True:
        return False
    if ev["readonly"] is False:
        return True
    return not ev["event"].startswith(("Describe", "List", "Get", "Head", "Lookup", "Search", "Query"))


# analytics
def build_findings(events):
    by_name = defaultdict(list)
    for ev in events:
        by_name[ev["event"]].append(ev)

    findings = []

    def add(fid, sev, hits, text_key=None):
        if not hits:
            return
        hits = sorted(hits, key=lambda e: e["dt"] or datetime.min.replace(tzinfo=timezone.utc))
        ok = [h for h in hits if not h["error"]]
        text_key = text_key or fid
        findings.append({
            "id": fid, "sev": sev, "title": T(text_key), "why": T(text_key + ".why"),
            "total": len(hits), "ok": len(ok), "denied": len(hits) - len(ok),
            "first": hits[0]["time"], "last": hits[-1]["time"],
            "events": Counter(h["event"] for h in hits),
            "regions": Counter(h["region"] for h in hits),
            "ips": Counter(h["ip"] for h in hits),
            "samples": [h for h in (ok or hits)[:8]],
        })

    for fid, sev, names in EVENT_RULES:
        add(fid, sev, [e for e in events if e["event"] in names])
    for fid, sev, text_key, sources in SOURCE_RULES:
        hits = [e for e in events if e["service"].startswith(sources)
                and e["event"] not in {n for _, _, ns in EVENT_RULES for n in ns}]
        add(fid, sev, hits, text_key)

    # bhvr
    denied = [e for e in events if e["error"]]
    if events and len(denied) >= 15 and len(denied) / len(events) > 0.25:
        add("ENUM", "MEDIUM", denied)

    autom = [e for e in events
             if any(tag in e["ua"].lower() for tag in AUTOMATION_UA) and not e["aws_internal"]]
    if autom:
        add("AUTOMATION", "MEDIUM", autom)

    fanout = Counter(e["region"] for e in events if not e["aws_internal"])
    if len(fanout) >= 5:
        findings.append({
            "id": "FANOUT", "sev": "MEDIUM",
            "title": T("FANOUT", len(fanout)),
            "why": T("FANOUT.why"),
            "total": sum(fanout.values()), "ok": 0, "denied": 0,
            "first": "", "last": "", "events": Counter(),
            "regions": fanout, "ips": Counter(), "samples": [],
        })

    # keys created during the window and then used
    made = {e["detail"].split("newkey=")[-1].split()[0]
            for e in by_name.get("CreateAccessKey", []) if "newkey=" in e["detail"]}
    used = {e["key"] for e in events}
    both = {k for k in made if k in used and k != "-"}
    if both:
        hits = [e for e in events if e["key"] in both]
        add("NEWKEY_USED", "CRITICAL", hits)

    findings.sort(key=lambda f: (SEV_ORDER.get(f["sev"], 9), -f["total"]))
    return findings


def sessions_of(events, gap_minutes):
    seq = sorted((e for e in events if e["dt"]), key=lambda e: e["dt"])
    out, cur = [], None
    for ev in seq:
        if cur and (ev["dt"] - cur["end"]) <= timedelta(minutes=gap_minutes):
            cur["end"] = ev["dt"]
            cur["n"] += 1
            cur["ips"][ev["ip"]] += 1
            cur["regions"][ev["region"]] += 1
            cur["events"][ev["event"]] += 1
            cur["denied"] += 1 if ev["error"] else 0
        else:
            if cur:
                out.append(cur)
            cur = {"start": ev["dt"], "end": ev["dt"], "n": 1,
                   "ips": Counter([ev["ip"]]), "regions": Counter([ev["region"]]),
                   "events": Counter([ev["event"]]), "denied": 1 if ev["error"] else 0}
    if cur:
        out.append(cur)
    return out


# output
def write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


def fmt(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%SZ") if dt else "?"


def main():
    global LANG
    ap = argparse.ArgumentParser(description="Triage CloudTrail dumps for a compromised access key incident")
    ap.add_argument("paths", nargs="+", help="JSON files or directories (.gz is fine)")
    ap.add_argument("-o", "--out", default="triage_out", help="output directory")
    ap.add_argument("--key", help="analyze only this AccessKeyId")
    ap.add_argument("--user", help="analyze only this principal name")
    ap.add_argument("--gap", type=int, default=30, help="gap in minutes that splits sessions (30)")
    ap.add_argument("--keep-aws-internal", action="store_true",
                    help="do not filter out calls made by AWS services themselves")
    ap.add_argument("-ru", "--ru", action="store_true",
                    help="write the report and console output in Russian (default: English)")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = ap.parse_args()
    LANG = 1 if args.ru else 0

    files = collect_inputs(args.paths)
    if not files:
        print(T("no_files"), file=sys.stderr)
        return 2

    raw = []
    for f in files:
        n = len(raw)
        raw.extend(load_file(f))
        print("  %-55s %6d" % (str(f)[-55:], len(raw) - n))

    if not raw:
        print(T("no_events"), file=sys.stderr)
        return 2

    events = [normalize(r) for r in raw]
    # dedupe by eventID (regional dumps overlap)
    seen, uniq = set(), []
    for ev in events:
        marker = ev["event_id"] or "%s|%s|%s|%s" % (ev["time"], ev["event"], ev["ip"], ev["region"])
        if marker in seen:
            continue
        seen.add(marker)
        uniq.append(ev)
    dropped_dupes = len(events) - len(uniq)
    events = uniq

    total_loaded = len(events)
    if not args.keep_aws_internal:
        events = [e for e in events if not e["aws_internal"]]
    if args.key:
        events = [e for e in events if e["key"] == args.key]
    if args.user:
        events = [e for e in events if e["principal"] == args.user]
    if not events:
        print(T("no_events_filtered"), file=sys.stderr)
        return 2

    events.sort(key=lambda e: e["dt"] or datetime.min.replace(tzinfo=timezone.utc))
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    times = [e["dt"] for e in events if e["dt"]]
    t0, t1 = (min(times), max(times)) if times else (None, None)

    #agr
    ips = defaultdict(lambda: {"n": 0, "denied": 0, "first": None, "last": None,
                               "regions": Counter(), "uas": Counter(),
                               "events": Counter(), "mut": 0})
    for e in events:
        s = ips[e["ip"]]
        s["n"] += 1
        s["denied"] += 1 if e["error"] else 0
        s["mut"] += 1 if (is_mutating(e) and not e["error"]) else 0
        s["regions"][e["region"]] += 1
        s["uas"][e["ua"]] += 1
        s["events"][e["event"]] += 1
        if e["dt"]:
            s["first"] = e["dt"] if not s["first"] else min(s["first"], e["dt"])
            s["last"] = e["dt"] if not s["last"] else max(s["last"], e["dt"])

    idents = defaultdict(lambda: {"n": 0, "denied": 0, "keys": Counter(), "ips": Counter(),
                                  "first": None, "last": None, "types": Counter()})
    for e in events:
        s = idents[e["principal"]]
        s["n"] += 1
        s["denied"] += 1 if e["error"] else 0
        s["keys"][e["key"]] += 1
        s["ips"][e["ip"]] += 1
        s["types"][e["itype"]] += 1
        if e["dt"]:
            s["first"] = e["dt"] if not s["first"] else min(s["first"], e["dt"])
            s["last"] = e["dt"] if not s["last"] else max(s["last"], e["dt"])

    findings = build_findings(events)
    sess = sessions_of(events, args.gap)

    per_min = Counter(e["dt"].strftime("%Y-%m-%d %H:%M") for e in events if e["dt"])
    peak = per_min.most_common(1)[0] if per_min else ("-", 0)

    ok_mut = [e for e in events if is_mutating(e) and not e["error"]]
    denied_mut = [e for e in events if is_mutating(e) and e["error"]]

    # tables CVS
    write_csv(out / "timeline.csv",
              ["time", "region", "service", "event", "principal", "itype", "access_key",
               "src_ip", "error", "detail", "user_agent", "errmsg", "event_id"],
              [[e["time"], e["region"], e["service"], e["event"], e["principal"], e["itype"],
                e["key"], e["ip"], e["error"], e["detail"], e["ua"], e["errmsg"], e["event_id"]]
               for e in events])

    write_csv(out / "ips.csv",
              ["ip", "events", "denied", "successful_mutating", "first_seen", "last_seen",
               "regions", "top_user_agent", "top_events"],
              [[ip, s["n"], s["denied"], s["mut"], fmt(s["first"]), fmt(s["last"]),
                " ".join(r for r, _ in s["regions"].most_common()),
                s["uas"].most_common(1)[0][0] if s["uas"] else "-",
                " ".join("%s(%d)" % (k, v) for k, v in s["events"].most_common(6))]
               for ip, s in sorted(ips.items(), key=lambda kv: -kv[1]["n"])])

    write_csv(out / "identities.csv",
              ["principal", "types", "events", "denied", "first_seen", "last_seen",
               "access_keys", "ips"],
              [[p, " ".join(s["types"]), s["n"], s["denied"], fmt(s["first"]), fmt(s["last"]),
                " ".join(k for k, _ in s["keys"].most_common()),
                " ".join(i for i, _ in s["ips"].most_common(10))]
               for p, s in sorted(idents.items(), key=lambda kv: -kv[1]["n"])])

    write_csv(out / "findings.csv",
              ["severity", "id", "title", "events_total", "successful", "denied",
               "first", "last", "regions", "top_ips", "why"],
              [[f["sev"], f["id"], f["title"], f["total"], f["ok"], f["denied"],
                f["first"], f["last"],
                " ".join(r for r, _ in f["regions"].most_common(8)),
                " ".join(i for i, _ in f["ips"].most_common(5)), f["why"]]
               for f in findings])

    ioc_ips = [ip for ip, s in sorted(ips.items(), key=lambda kv: -kv[1]["n"])
               if ip not in ("-",) and not ip.endswith(".amazonaws.com")]
    (out / "iocs_ip.txt").write_text("\n".join(ioc_ips) + "\n", encoding="utf-8")

    # report.md
    L = []
    A = L.append
    A(T("title"))
    A(T("generated", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")))
    A(T("h_summary"))
    A("| | |")
    A("|---|---|")
    A("| %s | %d |" % (T("s_loaded"), total_loaded))
    A("| %s | %d |" % (T("s_analyzed"), len(events)))
    if dropped_dupes:
        A("| %s | %d |" % (T("s_dupes"), dropped_dupes))
    A("| %s | %s -> %s |" % (T("s_window"), fmt(t0), fmt(t1)))
    if t0 and t1:
        A("| %s | %s |" % (T("s_duration"), str(t1 - t0)))
    A("| %s | %d |" % (T("s_ips"), len(ips)))
    A("| %s | %d |" % (T("s_regions"), len({e["region"] for e in events})))
    A("| %s | %d |" % (T("s_services"), len({e["service"] for e in events})))
    A("| %s | %d |" % (T("s_principals"), len(idents)))
    A("| %s | %d (%.0f%%) |" %
      (T("s_denied"), sum(1 for e in events if e["error"]),
       100.0 * sum(1 for e in events if e["error"]) / len(events)))
    A("| %s | %d |" % (T("s_ok_mut"), len(ok_mut)))
    A("| %s | %s |" % (T("s_peak"), T("s_peak_val", *peak)))
    A("")

    A(T("h_findings"))
    if not findings:
        A(T("no_findings"))
    for f in findings:
        A("### [%s] %s" % (f["sev"], f["title"]))
        A("")
        A(T("f_events", f["total"], f["ok"], f["denied"]))
        if f["first"]:
            A(T("f_period", f["first"], f["last"]))
        if f["events"]:
            A(T("f_calls", ", ".join("`%s` x%d" % (k, v) for k, v in f["events"].most_common(10))))
        if f["regions"]:
            A(T("f_regions", ", ".join("%s(%d)" % (k, v) for k, v in f["regions"].most_common(10))))
        if f["ips"]:
            A(T("f_ips", ", ".join("%s(%d)" % (k, v) for k, v in f["ips"].most_common(6))))
        A(T("f_why", f["why"]))
        if f["samples"]:
            A("")
            A("```")
            for s in f["samples"]:
                A("%s  %-14s %-30s %-16s %s %s" %
                  (s["time"], s["region"], s["event"], s["ip"],
                   ("[%s]" % s["error"]) if s["error"] else "[ok]", s["detail"]))
            A("```")
        A("")

    A(T("h_ips"))
    A(T("ips_header"))
    A("|---|---|---|---|---|---|---|---|")
    for ip, s in sorted(ips.items(), key=lambda kv: -kv[1]["n"])[:25]:
        A("| `%s` | %d | %d | %d | %s | %s | %d | %s |" %
          (ip, s["n"], s["denied"], s["mut"], fmt(s["first"]), fmt(s["last"]),
           len(s["regions"]), (s["uas"].most_common(1)[0][0] if s["uas"] else "-")[:45]))
    A("")
    A(T("ips_note"))

    A(T("h_sessions", args.gap))
    A(T("sess_header"))
    A("|---|---|---|---|---|---|---|---|")
    for i, s in enumerate(sess[:40], 1):
        A("| %d | %s | %s | %d | %d | %s | %d | %s |" %
          (i, fmt(s["start"]), fmt(s["end"]), s["n"], s["denied"],
           ", ".join(k for k, _ in s["ips"].most_common(3)), len(s["regions"]),
           ", ".join("%s x%d" % (k, v) for k, v in s["events"].most_common(4))))
    A("")

    A(T("h_blast"))
    A(T("blast_ok"))
    if ok_mut:
        for name, cnt in Counter(e["event"] for e in ok_mut).most_common(40):
            A("- `%s` x%d" % (name, cnt))
    else:
        A(T("blast_ok_none"))
    A("")
    A(T("blast_denied"))
    if denied_mut:
        for name, cnt in Counter(e["event"] for e in denied_mut).most_common(40):
            A("- `%s` x%d" % (name, cnt))
    else:
        A(T("blast_denied_none"))
    A("")

    A(T("h_top"))
    for name, cnt in Counter("%s:%s" % (e["service"], e["event"]) for e in events).most_common(30):
        A("- `%s` x%d" % (name, cnt))
    A("")

    A(T("h_limits"))
    for key in ("limit_data", "limit_90d", "limit_gaps", "limit_ip"):
        A("- %s" % T(key))
    A("")

    (out / "report.md").write_text("\n".join(L), encoding="utf-8")

    # cli
    print("\n" + "=" * 72)
    print(T("c_head", len(events), fmt(t0), fmt(t1), len(ips),
            len({e["region"] for e in events})))
    print("=" * 72)
    print(T("c_ips"))
    for ip, s in sorted(ips.items(), key=lambda kv: -kv[1]["n"])[:15]:
        print(T("c_ip_row", ip, s["n"], s["denied"], s["mut"],
                (s["uas"].most_common(1)[0][0] if s["uas"] else "-")[:40]))
    print(T("c_findings"))
    for f in findings:
        print(T("c_finding_row", f["sev"], f["title"][:50], f["total"], f["ok"]))
    print(T("c_written", out))
    return 0


if __name__ == "__main__":
    sys.exit(main())