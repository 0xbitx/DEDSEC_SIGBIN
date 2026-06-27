
<p align="center">
<img src="https://github.com/user-attachments/assets/f4a36958-01d4-4916-afc0-da320f89faf4", width="400", height="400">
</p>

<h1 align="center">SIGBIN</h1>

<p align="center">
  <strong>GTFOBins → Sigma & Wazuh Rules</strong><br>
  One command. Zero dependencies. Instant detection rules.
</p>

## DESCRIPTION

A standalone tool. Clones the latest GTFOBins data, parses every binary-abuse technique with a built-in YAML parser, and generates ready-to-deploy detection rules with regex patterns that match real attacker infrastructure.

---

## What It Does

| Step | Description |
|---|---|
| Clone | `git clone --depth 1` pulls latest [GTFOBins](https://github.com/GTFOBins/GTFOBins.github.io) |
| Parse | Built-in YAML parser reads every binary, flattens `contexts: {sudo, suid, unprivileged}` |
| Generate Sigma | Individual Sigma YAML rules with ATT&CK tags + embedded Wazuh mapping |
| Generate Wazuh | Individual Wazuh XML rules + combined `gtfobins_wazuh_rules.xml` |
| Cleanup | Removes cloned repo — only outputs remain |

---

## Usage

```bash
./dedsec_sigbin               # clone → Sigma + Wazuh (regex default)
./dedsec_sigbin --literal     # clone → Sigma + Wazuh (literal placeholders)
./dedsec_sigbin --sigma-only  # clone → Sigma only
./dedsec_sigbin --wazuh-only  # clone → Wazuh only
```

By default, documentation placeholders (`attacker.com`, `/path/to/input-file`, `12345`) are replaced with regex wildcards (`\S+`, `\d+`) so rules match real IPs, domains, paths, and ports. Use `--literal` to keep the raw GTFOBins strings.

---

## Output

```
gtfobins_wazuh_rules.xml        # combined Wazuh rules (drop-in ready)

sigma_rules/                    # individual Sigma YAML rules
  ├── bash_reverse_shell.yml
  ├── vim_shell.yml
  ├── find_sudo.yml
  └── ...

wazuh_rules/                    # individual Wazuh XML rules
  ├── bash_reverse_shell.xml
  ├── vim_shell.xml
  └── ...
```

### Sigma Rule (with embedded Wazuh mapping)

```yaml
title: Reverse Shell via bash
id: 13a40b1f-d0ed-576d-b1f3-c2b15a3ea760
status: experimental
description: Detects bash establishing a reverse shell to an attacker-controlled host.
references:
  - https://gtfobins.github.io/gtfobins/bash/
tags:
  - attack.t1059.004
  - attack.execution
  - attack.command_and_control
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith: /bash
    CommandLine|re: bash\ -c\ 'exec\ bash\ -i\ &>/dev/tcp/\S+/\d+\ <\&1'
  condition: selection
level: high
wazuh:
  purpose: wazuh_custom_rule
  rule_id: 100100
  level: 15
  if_sid: 530
  decoder: command
  match: bash
  regex: /bash$
```

### Wazuh Rule

```xml
<rule id="100100" level="15">
  <if_sid>530</if_sid>
  <match>bash</match>
  <regex>/bash$.*(?:bash\ \-c\ 'exec\ bash\ \-i\ \&gt;/dev/tcp/\S+/\d+\ \&lt;\&amp;1')</regex>
  <description>GTFOBins: Reverse Shell via bash</description>
  <mitre>
    <id>T1059.004</id>
  </mitre>
  <info type="link">https://gtfobins.github.io/gtfobins/bash/</info>
  <group>reverse_shell,command_and_control,gtfobins,</group>
</rule>
```

---

## Regex Mode (default)

Placeholders are replaced with wildcards so rules match real attacker infrastructure:

| Placeholder | Regex | Matches |
|---|---|---|
| `attacker.com` | `\S+` | `10.0.0.1`, `evil.c2.io` |
| `http://attacker.com` | `https?://\S+` | `https://cdn.bad.co` |
| `/path/to/input-file` | `\S+` | `/etc/shadow` |
| `12345`, `4444`, `1337` | `\d+` | any port |

**`--literal` (won't fire in production):**
```
CommandLine|contains: bash -c '...attacker.com/12345...'
```

**Default (catches real attacks):**
```
CommandLine|re: bash\ -c\ '...\S+/\d+...'
```

---

## Deploying to Wazuh

```bash
cp gtfobins_wazuh_rules.xml /var/ossec/etc/rules/
systemctl restart wazuh-manager
```

Rules use `<if_sid>530</if_sid>` (command execution decoder).

---

## ATT&CK Coverage

| Technique | Level | Description |
|---|---|---|
| **T1059.004** — Unix Shell | 12–15 | Shell spawning via abused binaries |
| **T1548.001** — SUID | 12 | SUID privilege escalation |
| **T1548.003** — Sudo | 12 | Sudo privilege escalation |
| **T1574** — Library Load | 12 | Shared library injection |
| **T1005** — File Read | 10 | Unauthorized file access |
| **T1048** — Exfiltration | 10 | File upload/exfiltration |
| **T1105** — Ingress Transfer | 10 | Remote file download |
| **T1564** — File Write | 10 | Unauthorized file writes |

### Wazuh Severity Levels

| Level | Meaning | Techniques |
|---|---|---|
| **15** | Highest — remote access | reverse-shell, bind-shell |
| **14** | High — non-interactive remote | non-interactive-reverse-shell |
| **12** | High — privilege escalation | shell, command, sudo, suid, library-load, capabilities |
| **10** | Medium — data access | file-read, file-write, file-upload, file-download |

---

## How It Works

```
┌──────────────┐     ┌──────────┐     ┌──────────────────────────┐
│  GTFOBins    │     │  sigbin  │     │  sigma_rules/            │
│  upstream    │ ──▶ │          │ ──▶ │  wazuh_rules/            │
│  (408+ bins) │     │  clone   │     │  gtfobins_wazuh_rules.xml│
│              │     │  +parse  │     │                          │
│              │     │  +gen    │     │                          │
└──────────────┘     └──────────┘     └──────────────────────────┘
```

1. **Clone** — `git clone --depth 1` pulls the latest GTFOBins YAML data
2. **Parse** — Built-in YAML parser reads the `contexts: {sudo, suid, unprivileged}` structure
3. **Generate** — Produces Sigma YAML (`CommandLine|re`) and Wazuh XML for each binary+technique
4. **Cleanup** — Removes the cloned repo, keeps only outputs

---

### INSTALLATION
    git clone https://github.com/0xbitx/DEDSEC_SIGBIN.git
    cd DEDSEC_SIGBIN
    chmod +x dedsec_sigbin
    ./dedsec_sigbin
    
### TESTED ON FOLLOWING
* Kali Linux 
* Parrot OS
* Ubuntu
  
