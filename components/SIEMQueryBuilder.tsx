'use client'

import React, { useState } from 'react'
import { copyToClipboard } from '@/lib/utils'

type Platform = 'splunk' | 'elastic' | 'kql' | 'qradar' | 'logscale' | 'sigma' | 'chronicle' | 'xql'

interface QueryTemplate {
  id: string
  name: string
  category: string
  description: string
  splunk: string
  elastic: string
  kql: string
  qradar: string
  logscale: string
  sigma: string
  chronicle: string
  xql: string
}

const TEMPLATES: QueryTemplate[] = [
  {
    id: 'failed-logins',
    name: 'Failed Login Attempts',
    category: 'Authentication',
    description: 'Detect multiple failed login attempts (brute force / password spray)',
    splunk: `index=windows EventCode=4625
| stats count by src_ip, user, dest_host
| where count > 5
| sort -count
| eval Risk = if(count > 20, "HIGH", if(count > 10, "MEDIUM", "LOW"))
| table src_ip, user, dest_host, count, Risk`,
    elastic: `GET /winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "winlog.event_id": 4625 } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "aggs": {
    "by_ip": {
      "terms": { "field": "source.ip", "size": 20 }
    }
  }
}`,
    kql: `SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts = count() by IpAddress, Account, Computer
| where FailedAttempts > 5
| sort by FailedAttempts desc
| extend Risk = iff(FailedAttempts > 20, "HIGH", iff(FailedAttempts > 10, "MEDIUM", "LOW"))`,
    qradar: `SELECT sourceip, username, destinationip, COUNT(*) AS event_count
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%Windows%'
  AND "EventID" = '4625'
GROUP BY sourceip, username, destinationip
HAVING COUNT(*) > 5
ORDER BY event_count DESC
LAST 1 HOURS`,
    logscale: `#event_id=4625
| groupBy([src_ip, user, dest_host], function=count(as=attempts))
| attempts > 5
| sort(attempts, order=desc)
| Risk := if(attempts > 20, then="HIGH", else=if(attempts > 10, then="MEDIUM", else="LOW"))`,
    sigma: `title: Multiple Failed Login Attempts - Brute Force
id: failed-logins-001
status: stable
level: medium
description: Detects multiple failed login attempts indicating brute force or password spray
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection | count(TargetUserName) by IpAddress > 5
  timeframe: 1h
falsepositives:
  - Users mistyping passwords
  - Service accounts with expired credentials
tags:
  - attack.credential_access
  - attack.t1110`,
    chronicle: `rule failed_login_brute_force {
  meta:
    author = "SOC Team"
    description = "Detect multiple failed login attempts"
    severity = "MEDIUM"
  events:
    $event.metadata.event_type = "USER_LOGIN"
    $event.metadata.vendor_name = "Microsoft"
    $event.security_result.action = "BLOCK"
    $event.security_result.summary = "4625"
    $event.principal.ip = $ip
    $event.target.user.userid = $user
  match:
    $ip, $user over 1h
  outcome:
    $risk_score = max(if(#event > 20, 85, if(#event > 10, 65, 35)))
  condition:
    #event > 5
}`,
    xql: `dataset = xdr_data
| filter event_id = 4625 AND event_type = ENUM.EVENT_LOG
| comp count(target_user) as attempts by src_ip, target_user, agent_hostname
| filter attempts > 5
| sort desc attempts
| alter risk = if(attempts > 20, "HIGH", if(attempts > 10, "MEDIUM", "LOW"))
| fields src_ip, target_user, agent_hostname, attempts, risk`,
  },
  {
    id: 'lateral-movement',
    name: 'Lateral Movement Detection',
    category: 'Lateral Movement',
    description: 'Detect lateral movement via PsExec, WMI, or SMB',
    splunk: `index=windows (EventCode=4648 OR EventCode=4624)
| eval src=coalesce(src_ip, src_host)
| where EventCode=4624 AND Logon_Type IN (3,10)
| stats count dc(dest_host) as unique_hosts by src, user
| where unique_hosts > 3
| sort -unique_hosts`,
    elastic: `GET /winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "terms": { "winlog.event_id": [4648, 4624] } },
        { "range": { "@timestamp": { "gte": "now-4h" } } }
      ]
    }
  }
}`,
    kql: `SecurityEvent
| where EventID in (4648, 4624)
| where LogonType in (3, 10)
| where TimeGenerated > ago(4h)
| summarize UniqueHosts = dcount(Computer), Count = count() by Account, IpAddress
| where UniqueHosts > 3
| sort by UniqueHosts desc`,
    qradar: `SELECT sourceip, username,
  COUNT(DISTINCT destinationip) AS unique_hosts,
  COUNT(*) AS event_count
FROM events
WHERE "EventID" IN ('4648', '4624')
  AND "LogonType" IN ('3', '10')
GROUP BY sourceip, username
HAVING COUNT(DISTINCT destinationip) > 3
ORDER BY unique_hosts DESC
LAST 4 HOURS`,
    logscale: `#event_id=/^(4648|4624)$/ logon_type IN [3, 10]
| groupBy([src_ip, user], function=[count(as=total), count(field=dest_host, distinct=true, as=unique_hosts)])
| unique_hosts > 3
| sort(unique_hosts, order=desc)`,
    sigma: `title: Lateral Movement via Network Logon
id: lateral-movement-001
status: stable
level: high
description: Detects lateral movement via PsExec, WMI, or SMB network logons to multiple hosts
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID:
      - 4648
      - 4624
    LogonType:
      - 3
      - 10
  condition: selection | count(Computer) by IpAddress > 3
  timeframe: 4h
falsepositives:
  - IT administrators performing legitimate remote management
  - Vulnerability scanners
tags:
  - attack.lateral_movement
  - attack.t1021`,
    chronicle: `rule lateral_movement_detection {
  meta:
    author = "SOC Team"
    description = "Detect lateral movement via network logons"
    severity = "HIGH"
  events:
    $event.metadata.event_type = "USER_LOGIN"
    $event.metadata.vendor_name = "Microsoft"
    ($event.security_result.summary = "4648" or $event.security_result.summary = "4624")
    $event.extensions.auth.mechanism = "NETWORK"
    $event.principal.ip = $src_ip
    $event.target.user.userid = $user
    $event.target.hostname = $dest
  match:
    $src_ip, $user over 4h
  outcome:
    $unique_hosts = count_distinct($dest)
  condition:
    $unique_hosts > 3
}`,
    xql: `dataset = xdr_data
| filter event_id in (4648, 4624) AND logon_type in (3, 10)
| comp count_distinct(agent_hostname) as unique_hosts, count(*) as total by src_ip, target_user
| filter unique_hosts > 3
| sort desc unique_hosts
| fields src_ip, target_user, unique_hosts, total`,
  },
  {
    id: 'powershell-suspicious',
    name: 'Suspicious PowerShell',
    category: 'Execution',
    description: 'Detect suspicious PowerShell execution patterns (encoded commands, download cradles)',
    splunk: `index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
  (EventCode=4104 OR EventCode=4103)
| where match(Message, "(?i)(invoke-expression|iex|downloadstring|webclient|encodedcommand|-enc|-w hidden|bypass|mimikatz|powersploit)")
| eval Severity=case(
    match(Message,"(?i)mimikatz|powersploit"), "CRITICAL",
    match(Message,"(?i)downloadstring|webclient"), "HIGH",
    true(), "MEDIUM")
| table _time, host, user, Message, Severity
| sort -_time`,
    elastic: `GET /winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "terms": { "winlog.event_id": [4104, 4103] } }
      ],
      "should": [
        { "match_phrase": { "message": "invoke-expression" } },
        { "match_phrase": { "message": "DownloadString" } },
        { "match_phrase": { "message": "encodedcommand" } },
        { "match_phrase": { "message": "bypass" } }
      ],
      "minimum_should_match": 1
    }
  }
}`,
    kql: `Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID in (4104, 4103)
| where TimeGenerated > ago(24h)
| where RenderedDescription has_any ("Invoke-Expression", "DownloadString", "EncodedCommand", "bypass", "hidden", "mimikatz")
| extend Severity = case(
    RenderedDescription has_any ("mimikatz", "powersploit"), "CRITICAL",
    RenderedDescription has_any ("DownloadString", "WebClient"), "HIGH",
    "MEDIUM")
| project TimeGenerated, Computer, UserName, RenderedDescription, Severity
| sort by TimeGenerated desc`,
    qradar: `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS event_time,
  sourceip, username, UTF8(payload) AS message
FROM events
WHERE LOGSOURCETYPENAME(logsourceid) ILIKE '%PowerShell%'
  AND "EventID" IN ('4104', '4103')
  AND (UTF8(payload) ILIKE '%Invoke-Expression%'
    OR UTF8(payload) ILIKE '%DownloadString%'
    OR UTF8(payload) ILIKE '%EncodedCommand%'
    OR UTF8(payload) ILIKE '%bypass%'
    OR UTF8(payload) ILIKE '%mimikatz%')
ORDER BY event_time DESC
LAST 24 HOURS`,
    logscale: `#source="WinEventLog:Microsoft-Windows-PowerShell/Operational" #event_id=/^(4104|4103)$/
| Message = /(?i)(invoke-expression|iex|downloadstring|webclient|encodedcommand|-enc|-w hidden|bypass|mimikatz|powersploit)/
| Severity := if(Message = /(?i)(mimikatz|powersploit)/, then="CRITICAL",
    else=if(Message = /(?i)(downloadstring|webclient)/, then="HIGH", else="MEDIUM"))
| select([@timestamp, host, user, Message, Severity])
| sort(@timestamp, order=desc)`,
    sigma: `title: Suspicious PowerShell Execution
id: powershell-suspicious-001
status: stable
level: high
description: Detects suspicious PowerShell execution patterns including encoded commands and download cradles
logsource:
  product: windows
  category: ps_script
  definition: Script block logging must be enabled
detection:
  selection_source:
    EventID:
      - 4104
      - 4103
  selection_keywords:
    ScriptBlockText|contains:
      - Invoke-Expression
      - IEX
      - DownloadString
      - WebClient
      - EncodedCommand
      - -enc
      - -w hidden
      - bypass
  selection_tools:
    ScriptBlockText|contains:
      - mimikatz
      - powersploit
  condition: selection_source and (selection_keywords or selection_tools)
falsepositives:
  - Legitimate administrative PowerShell scripts
  - Software deployment tools
tags:
  - attack.execution
  - attack.t1059.001`,
    chronicle: `rule suspicious_powershell_execution {
  meta:
    author = "SOC Team"
    description = "Detect suspicious PowerShell execution patterns"
    severity = "HIGH"
  events:
    $event.metadata.event_type = "PROCESS_LAUNCH"
    $event.target.process.file.full_path = /powershell/i
    (
      $event.target.process.command_line = /(?i)(invoke-expression|iex|downloadstring|webclient|encodedcommand|-enc|-w hidden|bypass)/ or
      $event.target.process.command_line = /(?i)(mimikatz|powersploit)/
    )
    $event.principal.hostname = $host
    $event.principal.user.userid = $user
  match:
    $host over 24h
  outcome:
    $risk_score = max(
      if($event.target.process.command_line = /(?i)(mimikatz|powersploit)/, 95,
      if($event.target.process.command_line = /(?i)(downloadstring|webclient)/, 75, 50))
    )
  condition:
    $event
}`,
    xql: `dataset = xdr_data
| filter event_type = ENUM.PROCESS AND action_process_image_name ~= "powershell"
| filter action_process_command_line ~= "(?i)(invoke-expression|iex|downloadstring|webclient|encodedcommand|-enc|-w hidden|bypass|mimikatz|powersploit)"
| alter severity = if(action_process_command_line ~= "(?i)(mimikatz|powersploit)", "CRITICAL",
    if(action_process_command_line ~= "(?i)(downloadstring|webclient)", "HIGH", "MEDIUM"))
| fields _time, agent_hostname, action_process_username, action_process_command_line, severity
| sort desc _time`,
  },
  {
    id: 'ransomware-activity',
    name: 'Ransomware Activity',
    category: 'Ransomware',
    description: 'Detect potential ransomware via rapid file modifications',
    splunk: `index=windows EventCode=4663 Object_Type=File
| eval file_ext=lower(replace(Object_Name, ".*\.", ""))
| where file_ext IN ("encrypted","locked","enc","crypto","crypt","locky","zepto","odin","aesir","thor","zzz")
    OR match(Object_Name, "(?i)(readme|recover|decrypt|ransom|how_to)")
| stats count, values(Object_Name) as files by host, user, _time span=1m
| where count > 20
| sort -count`,
    elastic: `GET /winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "winlog.event_id": 4663 } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ],
      "should": [
        { "wildcard": { "winlog.event_data.ObjectName": "*.encrypted" } },
        { "wildcard": { "winlog.event_data.ObjectName": "*README*" } },
        { "wildcard": { "winlog.event_data.ObjectName": "*DECRYPT*" } }
      ]
    }
  }
}`,
    kql: `SecurityEvent
| where EventID == 4663
| where ObjectType == "File"
| where TimeGenerated > ago(1h)
| where ObjectName has_any (".encrypted", ".locked", ".crypt", "README", "DECRYPT", "RANSOM")
| summarize FileCount = count(), Files = make_set(ObjectName, 10) by Account, Computer, bin(TimeGenerated, 1m)
| where FileCount > 20
| sort by FileCount desc`,
    qradar: `SELECT sourceip, username, LOGSOURCENAME(logsourceid) AS log_source,
  "ObjectName" AS file_name, COUNT(*) AS modification_count
FROM events
WHERE "EventID" = '4663'
  AND "ObjectType" = 'File'
  AND ("ObjectName" ILIKE '%.encrypted%'
    OR "ObjectName" ILIKE '%.locked%'
    OR "ObjectName" ILIKE '%.crypt%'
    OR "ObjectName" ILIKE '%README%'
    OR "ObjectName" ILIKE '%DECRYPT%'
    OR "ObjectName" ILIKE '%RANSOM%')
GROUP BY sourceip, username, log_source, file_name
HAVING COUNT(*) > 20
ORDER BY modification_count DESC
LAST 1 HOURS`,
    logscale: `#event_id=4663 ObjectType=File
| ObjectName = /(?i)\.(encrypted|locked|enc|crypto|crypt|locky|zepto|zzz)$|(?i)(readme|recover|decrypt|ransom|how_to)/
| bucket(field=@timestamp, span=1m, function=count(as=file_count))
| groupBy([host, user, _bucket], function=[count(as=file_count), collect(ObjectName, limit=10)])
| file_count > 20
| sort(file_count, order=desc)`,
    sigma: `title: Ransomware File Activity
id: ransomware-activity-001
status: stable
level: critical
description: Detects potential ransomware via rapid file modifications with suspicious extensions
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4663
    ObjectType: File
  keywords_ext:
    ObjectName|endswith:
      - .encrypted
      - .locked
      - .enc
      - .crypto
      - .crypt
      - .locky
      - .zepto
      - .zzz
  keywords_ransom:
    ObjectName|contains:
      - README
      - RECOVER
      - DECRYPT
      - RANSOM
      - HOW_TO
  condition: selection and (keywords_ext or keywords_ransom) | count() by Computer > 20
  timeframe: 1m
falsepositives:
  - Legitimate encryption tools
  - Backup software creating encrypted archives
tags:
  - attack.impact
  - attack.t1486`,
    chronicle: `rule ransomware_file_activity {
  meta:
    author = "SOC Team"
    description = "Detect potential ransomware via rapid file modifications"
    severity = "CRITICAL"
  events:
    $event.metadata.event_type = "FILE_MODIFICATION"
    $event.metadata.vendor_name = "Microsoft"
    $event.security_result.summary = "4663"
    (
      re.regex($event.target.file.full_path, \`\\.(encrypted|locked|enc|crypto|crypt|locky|zepto|zzz)$\`) or
      re.regex($event.target.file.full_path, \`(?i)(readme|recover|decrypt|ransom|how_to)\`)
    )
    $event.principal.hostname = $host
    $event.principal.user.userid = $user
  match:
    $host, $user over 1m
  outcome:
    $risk_score = max(95)
    $file_count = count($event.target.file.full_path)
  condition:
    #event > 20
}`,
    xql: `dataset = xdr_data
| filter event_id = 4663 AND event_sub_type = ENUM.FILE
| filter action_file_name ~= "(?i)\\.(encrypted|locked|enc|crypto|crypt|locky|zepto|zzz)$" OR action_file_name ~= "(?i)(readme|recover|decrypt|ransom|how_to)"
| comp count(*) as file_count, values(action_file_path) as files by agent_hostname, action_process_username, bin(_time, 1m)
| filter file_count > 20
| sort desc file_count
| fields agent_hostname, action_process_username, file_count, files`,
  },
  {
    id: 'dns-tunneling',
    name: 'DNS Tunneling Detection',
    category: 'Exfiltration',
    description: 'Detect potential DNS tunneling via high query volume or long domain names',
    splunk: `index=dns
| eval domain_len=len(query)
| eval subdomain_depth=mvcount(split(query,"."))
| where domain_len > 50 OR subdomain_depth > 5
| stats count, avg(domain_len) as avg_len, dc(query) as unique_domains by src_ip
| where count > 100 OR avg_len > 60
| sort -count`,
    elastic: `GET /packetbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "type": "dns" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } },
        { "range": { "dns.question.name.length": { "gte": 50 } } }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "source.ip", "size": 20 }
    }
  }
}`,
    kql: `DnsEvents
| where TimeGenerated > ago(1h)
| extend DomainLength = strlen(Name)
| extend SubdomainDepth = array_length(split(Name, "."))
| where DomainLength > 50 or SubdomainDepth > 5
| summarize QueryCount = count(), AvgDomainLen = avg(DomainLength), UniqueDomains = dcount(Name) by ClientIP
| where QueryCount > 100 or AvgDomainLen > 60
| sort by QueryCount desc`,
    qradar: `SELECT sourceip,
  COUNT(*) AS query_count,
  AVG(STRLEN("dns_query")) AS avg_domain_length,
  COUNT(DISTINCT "dns_query") AS unique_domains
FROM events
WHERE CATEGORYNAME(category) = 'DNS'
  AND STRLEN("dns_query") > 50
GROUP BY sourceip
HAVING COUNT(*) > 100 OR AVG(STRLEN("dns_query")) > 60
ORDER BY query_count DESC
LAST 1 HOURS`,
    logscale: `#type=dns
| domain_len := length(query)
| subdomain_depth := length(splitString(query, "."))
| domain_len > 50 OR subdomain_depth > 5
| groupBy(src_ip, function=[count(as=query_count), avg(domain_len, as=avg_len), count(field=query, distinct=true, as=unique_domains)])
| query_count > 100 OR avg_len > 60
| sort(query_count, order=desc)`,
    sigma: `title: DNS Tunneling Detection
id: dns-tunneling-001
status: stable
level: high
description: Detects potential DNS tunneling via high query volume or unusually long domain names
logsource:
  category: dns
detection:
  selection:
    query|re: '.{50,}'
  condition: selection | count() by src_ip > 100
  timeframe: 1h
falsepositives:
  - CDN domains with long subdomains
  - Legitimate services with auto-generated domain names
tags:
  - attack.exfiltration
  - attack.t1071.004
  - attack.command_and_control`,
    chronicle: `rule dns_tunneling_detection {
  meta:
    author = "SOC Team"
    description = "Detect potential DNS tunneling via high query volume or long domains"
    severity = "HIGH"
  events:
    $event.metadata.event_type = "NETWORK_DNS"
    strings.length($event.network.dns.questions.name) > 50
    $event.principal.ip = $src_ip
  match:
    $src_ip over 1h
  outcome:
    $query_count = count($event.metadata.id)
    $avg_length = mean(strings.length($event.network.dns.questions.name))
    $risk_score = max(if($query_count > 500, 90, if($query_count > 100, 70, 50)))
  condition:
    $query_count > 100 or $avg_length > 60
}`,
    xql: `dataset = xdr_data
| filter event_type = ENUM.DNS
| alter domain_len = length(action_external_hostname)
| alter subdomain_depth = array_length(split(action_external_hostname, "."))
| filter domain_len > 50 OR subdomain_depth > 5
| comp count(*) as query_count, avg(domain_len) as avg_len, count_distinct(action_external_hostname) as unique_domains by src_ip
| filter query_count > 100 OR avg_len > 60
| sort desc query_count`,
  },
  {
    id: 'privilege-escalation',
    name: 'Privilege Escalation',
    category: 'Privilege Escalation',
    description: 'Detect user privilege escalation events',
    splunk: `index=windows (EventCode=4728 OR EventCode=4732 OR EventCode=4756 OR EventCode=4672)
| eval group_name=coalesce(Group_Name, MemberName)
| where group_name IN ("Administrators","Domain Admins","Enterprise Admins","Schema Admins","Account Operators")
| table _time, EventCode, host, user, group_name, src_ip
| sort -_time`,
    elastic: `GET /winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "terms": { "winlog.event_id": [4728, 4732, 4756, 4672] } },
        { "range": { "@timestamp": { "gte": "now-24h" } } }
      ]
    }
  }
}`,
    kql: `SecurityEvent
| where EventID in (4728, 4732, 4756, 4672)
| where TimeGenerated > ago(24h)
| where TargetUserName has_any ("Administrators", "Domain Admins", "Enterprise Admins")
    or Activity has "special privileges"
| project TimeGenerated, Activity, SubjectAccount, TargetAccount, TargetUserName, Computer, IpAddress
| sort by TimeGenerated desc`,
    qradar: `SELECT DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm:ss') AS event_time,
  sourceip, username, "EventID",
  "TargetUserName" AS target_group,
  LOGSOURCENAME(logsourceid) AS log_source
FROM events
WHERE "EventID" IN ('4728', '4732', '4756', '4672')
  AND ("TargetUserName" ILIKE '%Administrators%'
    OR "TargetUserName" ILIKE '%Domain Admins%'
    OR "TargetUserName" ILIKE '%Enterprise Admins%'
    OR "TargetUserName" ILIKE '%Schema Admins%')
ORDER BY event_time DESC
LAST 24 HOURS`,
    logscale: `#event_id=/^(4728|4732|4756|4672)$/
| group_name = /(?i)(Administrators|Domain Admins|Enterprise Admins|Schema Admins|Account Operators)/
    OR Activity = /special privileges/
| select([@timestamp, EventCode, host, user, group_name, src_ip])
| sort(@timestamp, order=desc)`,
    sigma: `title: Privilege Escalation - Admin Group Modification
id: privilege-escalation-001
status: stable
level: high
description: Detects user privilege escalation via addition to privileged groups
logsource:
  product: windows
  service: security
detection:
  selection_events:
    EventID:
      - 4728
      - 4732
      - 4756
      - 4672
  selection_groups:
    TargetUserName|contains:
      - Administrators
      - Domain Admins
      - Enterprise Admins
      - Schema Admins
      - Account Operators
  condition: selection_events and selection_groups
falsepositives:
  - Planned administrative changes
  - IT onboarding processes
tags:
  - attack.privilege_escalation
  - attack.t1078.002`,
    chronicle: `rule privilege_escalation_detection {
  meta:
    author = "SOC Team"
    description = "Detect privilege escalation via admin group modifications"
    severity = "HIGH"
  events:
    $event.metadata.event_type = "GROUP_MODIFICATION"
    $event.metadata.vendor_name = "Microsoft"
    (
      $event.security_result.summary = "4728" or
      $event.security_result.summary = "4732" or
      $event.security_result.summary = "4756" or
      $event.security_result.summary = "4672"
    )
    (
      $event.target.group.group_display_name = /(?i)(Administrators|Domain Admins|Enterprise Admins|Schema Admins)/ or
      $event.security_result.description = /special privileges/
    )
    $event.principal.user.userid = $actor
  match:
    $actor over 24h
  outcome:
    $risk_score = max(80)
  condition:
    $event
}`,
    xql: `dataset = xdr_data
| filter event_id in (4728, 4732, 4756, 4672) AND event_type = ENUM.EVENT_LOG
| filter target_user ~= "(?i)(Administrators|Domain Admins|Enterprise Admins|Schema Admins|Account Operators)" OR action_evtlog_description ~= "special privileges"
| fields _time, event_id, agent_hostname, actor, target_user, src_ip
| sort desc _time`,
  },
  {
    id: 'data-exfiltration',
    name: 'Data Exfiltration',
    category: 'Exfiltration',
    description: 'Detect large data transfers to external destinations',
    splunk: `index=network
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port
| where total_bytes > 104857600
| eval MB = round(total_bytes/1048576, 2)
| where NOT cidrmatch("10.0.0.0/8", dest_ip)
    AND NOT cidrmatch("172.16.0.0/12", dest_ip)
    AND NOT cidrmatch("192.168.0.0/16", dest_ip)
| sort -MB
| table src_ip, dest_ip, dest_port, MB`,
    elastic: `GET /packetbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ],
      "must_not": [
        { "cidr": { "network.destination.ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] } }
      ]
    }
  },
  "aggs": {
    "by_src": {
      "terms": { "field": "source.ip" },
      "aggs": { "total_bytes": { "sum": { "field": "network.bytes" } } }
    }
  }
}`,
    kql: `AzureNetworkAnalytics_CL
| where TimeGenerated > ago(1h)
| where SubType_s == "FlowLog"
| where not(ipv4_is_private(DestIP_s))
| summarize TotalBytesSent = sum(OutboundBytes_d) by SrcIP_s, DestIP_s, DestPort_d
| where TotalBytesSent > 104857600
| extend MB = round(TotalBytesSent / 1048576, 2)
| sort by MB desc`,
    qradar: `SELECT sourceip, destinationip, destinationport,
  SUM(bytesreceived) AS total_bytes,
  ROUND(SUM(bytesreceived) / 1048576, 2) AS mb_transferred
FROM flows
WHERE destinationip NOT INCIDR '10.0.0.0/8'
  AND destinationip NOT INCIDR '172.16.0.0/12'
  AND destinationip NOT INCIDR '192.168.0.0/16'
GROUP BY sourceip, destinationip, destinationport
HAVING SUM(bytesreceived) > 104857600
ORDER BY total_bytes DESC
LAST 1 HOURS`,
    logscale: `#type=network
| !cidr(dest_ip, subnet="10.0.0.0/8") AND !cidr(dest_ip, subnet="172.16.0.0/12") AND !cidr(dest_ip, subnet="192.168.0.0/16")
| groupBy([src_ip, dest_ip, dest_port], function=sum(bytes_out, as=total_bytes))
| total_bytes > 104857600
| MB := total_bytes / 1048576
| MB := format("%,.2f", field=MB)
| sort(total_bytes, order=desc)`,
    sigma: `title: Large Data Exfiltration to External Host
id: data-exfiltration-001
status: stable
level: high
description: Detects large data transfers to external (non-RFC1918) destinations
logsource:
  category: firewall
detection:
  selection:
    dst_ip|cidr:
      - '!10.0.0.0/8'
      - '!172.16.0.0/12'
      - '!192.168.0.0/16'
  condition: selection | sum(bytes_out) by src_ip > 104857600
  timeframe: 1h
falsepositives:
  - Large file uploads to cloud storage
  - Video conferencing
  - Backup operations to cloud providers
tags:
  - attack.exfiltration
  - attack.t1048`,
    chronicle: `rule data_exfiltration_detection {
  meta:
    author = "SOC Team"
    description = "Detect large data transfers to external destinations"
    severity = "HIGH"
  events:
    $event.metadata.event_type = "NETWORK_CONNECTION"
    not net.ip_in_range_cidr($event.target.ip, "10.0.0.0/8")
    not net.ip_in_range_cidr($event.target.ip, "172.16.0.0/12")
    not net.ip_in_range_cidr($event.target.ip, "192.168.0.0/16")
    $event.network.sent_bytes > 0
    $event.principal.ip = $src_ip
    $event.target.ip = $dest_ip
  match:
    $src_ip, $dest_ip over 1h
  outcome:
    $total_bytes = sum($event.network.sent_bytes)
    $mb_sent = div(sum($event.network.sent_bytes), 1048576)
    $risk_score = max(if($total_bytes > 524288000, 90, 70))
  condition:
    $total_bytes > 104857600
}`,
    xql: `dataset = xdr_data
| filter event_type = ENUM.NETWORK
| filter dst_ip !~= "^10\\." AND dst_ip !~= "^172\\.(1[6-9]|2[0-9]|3[01])\\." AND dst_ip !~= "^192\\.168\\."
| comp sum(upload_bytes) as total_bytes by src_ip, dst_ip, dst_port
| filter total_bytes > 104857600
| alter MB = round(divide(total_bytes, 1048576), 2)
| sort desc MB
| fields src_ip, dst_ip, dst_port, MB`,
  },
  {
    id: 'c2-beaconing',
    name: 'C2 Beaconing Detection',
    category: 'Command & Control',
    description: 'Detect regular beaconing patterns typical of C2 malware',
    splunk: `index=proxy OR index=network
| bucket _time span=5m
| stats count by _time, src_ip, dest_ip, dest_port
| eventstats avg(count) as avg_count, stdev(count) as std_count by src_ip, dest_ip
| eval jitter = std_count / avg_count
| where jitter < 0.1 AND avg_count > 1
| stats count as beacon_intervals, avg(jitter) as avg_jitter by src_ip, dest_ip, dest_port
| where beacon_intervals > 12
| sort -beacon_intervals`,
    elastic: `GET /packetbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-6h" } } }
      ]
    }
  },
  "aggs": {
    "by_connection": {
      "composite": {
        "sources": [
          { "src": { "terms": { "field": "source.ip" } } },
          { "dst": { "terms": { "field": "destination.ip" } } }
        ]
      },
      "aggs": {
        "by_time": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "5m" }
        }
      }
    }
  }
}`,
    kql: `CommonSecurityLog
| where TimeGenerated > ago(6h)
| summarize ConnectionCount = count() by SourceIP, DestinationIP, DestinationPort, bin(TimeGenerated, 5m)
| summarize AvgCount = avg(ConnectionCount), StdDev = stdev(ConnectionCount), Intervals = count() by SourceIP, DestinationIP, DestinationPort
| extend Jitter = StdDev / AvgCount
| where Jitter < 0.15 and Intervals > 12
| sort by Jitter asc`,
    qradar: `SELECT sourceip, destinationip, destinationport,
  COUNT(*) AS connection_count,
  AVG(eventcount) AS avg_events,
  STDEV(eventcount) AS std_events
FROM events
WHERE CATEGORYNAME(category) IN ('Firewall Session Opened', 'Proxy Traffic')
GROUP BY sourceip, destinationip, destinationport,
  DATEFORMAT(starttime, 'yyyy-MM-dd HH:mm') AS time_bucket
HAVING STDEV(eventcount) / AVG(eventcount) < 0.1
  AND COUNT(*) > 12
ORDER BY connection_count DESC
LAST 6 HOURS`,
    logscale: `#type=/^(proxy|network)$/
| bucket(field=@timestamp, span=5m)
| groupBy([_bucket, src_ip, dest_ip, dest_port], function=count(as=conn_count))
| groupBy([src_ip, dest_ip, dest_port], function=[avg(conn_count, as=avg_count), stdDev(conn_count, as=std_count), count(as=intervals)])
| jitter := std_count / avg_count
| jitter < 0.1 AND avg_count > 1 AND intervals > 12
| sort(intervals, order=desc)`,
    sigma: `title: C2 Beaconing Pattern Detection
id: c2-beaconing-001
status: experimental
level: high
description: Detects regular beaconing patterns with low jitter typical of C2 malware communication
logsource:
  category: proxy
detection:
  selection:
    c-uri|re: '.*'
  condition: selection
  timeframe: 6h
falsepositives:
  - Legitimate heartbeat or keepalive connections
  - Software update checks
  - NTP synchronization
tags:
  - attack.command_and_control
  - attack.t1071
  - attack.t1573`,
    chronicle: `rule c2_beaconing_detection {
  meta:
    author = "SOC Team"
    description = "Detect regular beaconing patterns typical of C2 malware"
    severity = "HIGH"
  events:
    $event.metadata.event_type = "NETWORK_CONNECTION"
    $event.principal.ip = $src_ip
    $event.target.ip = $dest_ip
    $event.target.port = $dest_port
  match:
    $src_ip, $dest_ip, $dest_port over 6h
  outcome:
    $connection_count = count($event.metadata.id)
    $risk_score = max(if($connection_count > 50, 85, if($connection_count > 20, 70, 50)))
  condition:
    $connection_count > 12
}`,
    xql: `dataset = xdr_data
| filter event_type = ENUM.NETWORK
| bin _time to 5m as time_bucket
| comp count(*) as conn_count by time_bucket, src_ip, dst_ip, dst_port
| comp avg(conn_count) as avg_count, stddev(conn_count) as std_count, count(*) as intervals by src_ip, dst_ip, dst_port
| alter jitter = divide(std_count, avg_count)
| filter jitter < 0.1 AND avg_count > 1 AND intervals > 12
| sort asc jitter
| fields src_ip, dst_ip, dst_port, avg_count, jitter, intervals`,
  },
]

const CATEGORIES = ['All', ...Array.from(new Set(TEMPLATES.map(t => t.category)))]

const PLATFORM_LABELS: Record<Platform, { name: string; color: string }> = {
  splunk: { name: 'Splunk SPL', color: '#ff6b35' },
  elastic: { name: 'Elastic DSL', color: '#ffd700' },
  kql: { name: 'KQL (Azure Sentinel)', color: '#00d4ff' },
  qradar: { name: 'IBM QRadar (AQL)', color: '#be95ff' },
  logscale: { name: 'CrowdStrike LogScale', color: '#ff4444' },
  sigma: { name: 'Sigma Rules', color: '#4ade80' },
  chronicle: { name: 'Google Chronicle (YARA-L)', color: '#4ecdc4' },
  xql: { name: 'Palo Alto Cortex XDR (XQL)', color: '#ff8c42' },
}

const ALL_PLATFORMS = Object.keys(PLATFORM_LABELS) as Platform[]

export default function SIEMQueryBuilder() {
  const [platform, setPlatform] = useState<Platform>('splunk')
  const [category, setCategory] = useState('All')
  const [selected, setSelected] = useState<QueryTemplate>(TEMPLATES[0])
  const [customQuery, setCustomQuery] = useState('')
  const [copied, setCopied] = useState('')
  const [showCustom, setShowCustom] = useState(false)

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  const filtered = TEMPLATES.filter(t => category === 'All' || t.category === category)

  return (
    <div className="space-y-5">
      <div>
        <h2 className="section-heading">SIEM Query Builder</h2>
        <p className="section-subheading">Ready-to-use detection queries for Splunk, Elastic, Azure Sentinel, QRadar, CrowdStrike LogScale, Sigma, Chronicle &amp; Cortex XDR</p>
      </div>

      {/* Platform selector */}
      <div className="card">
        <div className="card-header"><span className="card-title">Target Platform</span></div>
        <div className="flex flex-wrap gap-2">
          {ALL_PLATFORMS.map(p => (
            <button
              key={p}
              onClick={() => setPlatform(p)}
              className={`tab-btn ${platform === p ? 'active' : ''}`}
              style={platform === p ? { color: PLATFORM_LABELS[p].color, borderColor: PLATFORM_LABELS[p].color } : {}}
            >
              {PLATFORM_LABELS[p].name}
            </button>
          ))}
        </div>
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        {/* Template list */}
        <div className="space-y-3">
          <div className="card">
            <div className="card-header"><span className="card-title">Query Templates</span></div>
            <div className="flex flex-wrap gap-1 mb-3">
              {CATEGORIES.map(c => (
                <button key={c} onClick={() => setCategory(c)} className={`tab-btn text-xs ${category === c ? 'active' : ''}`}>{c}</button>
              ))}
            </div>
            <div className="space-y-1">
              {filtered.map(t => (
                <button
                  key={t.id}
                  onClick={() => setSelected(t)}
                  className={`w-full text-left p-2 rounded transition-all ${selected.id === t.id ? 'border-glow-blue' : ''}`}
                  style={{ background: 'rgba(10,20,40,0.6)', border: `1px solid ${selected.id === t.id ? 'rgba(0,212,255,0.4)' : 'rgba(0,212,255,0.08)'}` }}
                >
                  <div className="text-xs font-medium text-gray-200">{t.name}</div>
                  <div className="text-xs text-gray-500 mt-0.5">{t.category}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Query panel */}
        <div className="md:col-span-2 space-y-4">
          <div className="card">
            <div className="flex items-start justify-between flex-wrap gap-2 mb-3">
              <div>
                <div className="text-sm font-semibold text-gray-200">{selected.name}</div>
                <div className="text-xs text-gray-500 mt-0.5">{selected.description}</div>
              </div>
              <div className="flex gap-2">
                <span className="badge badge-info">{selected.category}</span>
                <button
                  onClick={() => copy(selected[platform], `query-${selected.id}`)}
                  className="btn-primary text-xs py-1"
                >
                  {copied === `query-${selected.id}` ? '✓ Copied!' : 'Copy Query'}
                </button>
              </div>
            </div>
            <div className="text-xs text-gray-500 mb-2" style={{ color: PLATFORM_LABELS[platform].color }}>
              ● {PLATFORM_LABELS[platform].name}
            </div>
            <pre className="code-block text-xs overflow-x-auto whitespace-pre-wrap">{selected[platform]}</pre>
          </div>

          {/* All platforms side by side */}
          <div className="card">
            <div className="card-header"><span className="card-title">All Platform Variants</span></div>
            <div className="space-y-4">
              {ALL_PLATFORMS.map(p => (
                <div key={p}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold" style={{ color: PLATFORM_LABELS[p].color }}>{PLATFORM_LABELS[p].name}</span>
                    <button onClick={() => copy(selected[p], `all-${p}`)} className="text-xs text-blue-400 hover:underline">
                      {copied === `all-${p}` ? '✓ Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre className="code-block text-xs overflow-x-auto whitespace-pre-wrap">{selected[p]}</pre>
                </div>
              ))}
            </div>
          </div>

          {/* Custom query builder */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Custom Query Notepad</span>
              <button onClick={() => setShowCustom(!showCustom)} className="ml-auto text-xs text-blue-400">{showCustom ? 'Hide' : 'Show'}</button>
            </div>
            {showCustom && (
              <div>
                <textarea
                  className="cyber-textarea w-full h-40 font-mono text-xs"
                  value={customQuery}
                  onChange={e => setCustomQuery(e.target.value)}
                  placeholder={`Write your custom ${PLATFORM_LABELS[platform].name} query here...`}
                />
                <div className="flex gap-2 mt-2">
                  <button onClick={() => copy(customQuery, 'custom')} disabled={!customQuery.trim()} className="btn-primary text-xs disabled:opacity-50">
                    {copied === 'custom' ? '✓ Copied' : 'Copy Query'}
                  </button>
                  <button onClick={() => setCustomQuery('')} className="btn-danger text-xs">Clear</button>
                </div>
              </div>
            )}
          </div>

          {/* Query tuning tips */}
          <div className="card">
            <div className="card-header"><span className="card-title">Query Tuning Tips</span></div>
            <div className="space-y-2 text-xs text-gray-400">
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Adjust time ranges to balance coverage vs. performance (start with 1h, expand if needed)</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Add your environment&apos;s known-good IPs to exclusion lists to reduce false positives</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Tune threshold values (count &gt; N) based on your baseline traffic</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Test queries in development before applying to production alerts</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Document all custom queries with description, author, and date</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Map queries to MITRE ATT&amp;CK techniques for better coverage visibility</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Use Sigma rules as vendor-agnostic templates, then convert to your platform&apos;s native syntax</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Validate Chronicle YARA-L rules in the Rule Editor before deploying to production</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
