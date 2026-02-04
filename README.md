# The Eternel Lore of Kiana CTF – Full Walkthrough

This walkthrough covers the complete investigation from initial alert to final data exfiltration, showing how all three flags were found using Kibana/Elastic. The challenge simulates a realistic DFIR/SOC investigation involving LFI, secret leakage, attempted RCE, and DNS tunneling.

---

## 🧩 Challenge Summary

**Objective**: Investigate a security incident on a development server and identify:
1. The initial breach
2. What sensitive data was exposed
3. How data was exfiltrated

**Final Answer Format**:
```
FLAG{example1}+FLAG{example2}+FLAG{example3}
```

---

## 🏁 Flag 1 – Initial Breach (Web-Ingress)

### 🔍 Where to Look
**Index**: `web-ingress`

### 🔎 What Happened
An attacker exploited a **path traversal (LFI)** vulnerability in the Chimera web application to read internal configuration files.

### 📌 Key Log Entry
```
url.path: /static/..%2f..%2f..%2f..%2f..%2f..%2fopt/chimera/config/app.properties
response.status_code: 200
```

The response body exposed database credentials.

### 🔐 Decoding the Secret
The database password was hex-encoded:
```
464c41477b3173745f464c40475f504154485f325f50574e447d
```

Decoded (hex → ASCII):
```
FLAG{1st_FL@G_PATH_2_PWND}
```

✅ **Flag 1 found**

---

## 🏁 Flag 2 – Config Leak → RCE Attempt (OSSEC Alerts)

### 🔍 Where to Look
**Index**: `ossec-alerts`

### 🔎 What Happened
OSSEC logged the EC2 **user-data bootstrap script**, which contained a hardcoded backup secret written to a log file.

### 📌 Key Log Entry
```
user_data.decoded:
#!/bin/bash
...
echo 'BQ9NMB7g5vUypsrb1u73PSEPcEy5c5LLx1BSEuWgLULT63aaN4Eg' > /var/log/dev_setup.log
```

### 🔐 Decoding the Secret
The string is Base64-encoded.

Decoded:
```
FLAG{2nd_FL@G_C0NF1G_L34K_L34DS_2_RCE}
```

This explains how the attacker escalated from config exposure toward remote code execution.

✅ **Flag 2 found**

---

## 🏁 Flag 3 – Data Exfiltration via DNS Tunneling

### 🔍 Where to Look
**Index**: `firewall`

### 🧠 Clue from the Challenge Description
> “Our systems detected a pattern of suspicious DNS traffic, suggesting someone might be stealing data.”

This strongly hints at **DNS tunneling**.

---

### 🔎 Step 1: Identify Suspicious Domains

Inspect `dns.question.name` field statistics. Most traffic goes to common domains (Google, GitHub, AWS), but three domains stand out with **<0.1% frequency**:

```
RPU2QKTKQZVEWL5EJ6Q.ch-data.live
MN5QWIIR2EAREMTCBI55TG4TE.ch-data.live
ITQOJXXA4TJMV2GC4TZL52HEY.ch-data.live
```

Rare + high-entropy subdomains = classic DNS exfiltration.

---

### 🔎 Step 2: Filter All Exfil Traffic

KQL query used:
```
dns.question.name.keyword : "*ch-data.live"
```

This returns all DNS queries used in the exfiltration channel.

---

### 🔎 Step 3: Extract the Payload

Take **only the left-most subdomain labels**, concatenate them in timestamp order:

```
PMRHA4TPNJSWG5BCHIQCEQ3INFWWK4TBEIWCAITBOV2GQ33SL5RW63LNNF2F62LEEI5CAITEPFWGC3RNNUWWM2LOMFWC24DVONUCELBAEJQWYZ3POJUXI2DNEI5CAITQOJXXA4TJMV2GC4TZL52HEYLOONTG64TNMVZCELBAEJYGC6LMN5QWIIR2EAREMTCBI55TG4TEL5DEYQCHL5CE4U27KRKU4TRTJRPU2QKTKQZVEWL5EJ6Q
```

---

### 🔐 Step 4: Decode (Base32)

Decode the full string using Base32 (CyberChef → From Base32).

### 📤 Decoded Output
```
{
  "project": "Chimera",
  "author_commit_id": "dylan-m-final-push",
  "algorithm": "proprietary_transformer",
  "payload": "FLAG{3rd_FL@G_DNS_TUNN3L_MAST3RY}"
}
```

✅ **Flag 3 found**

---

## 🏁 Final Answer

```
FLAG{1st_FL@G_PATH_2_PWND}+FLAG{2nd_FL@G_C0NF1G_L34K_L34DS_2_RCE}+FLAG{3rd_FL@G_DNS_TUNN3L_MAST3RY}
```

---

## 🧠 Skills Demonstrated

- Web exploitation (LFI)
- Secret decoding (hex, Base64, Base32)
- Cloud-init & user-data analysis
- OSSEC alert interpretation
- DNS tunneling detection
- Log correlation across multiple indices

This challenge closely mirrors **real-world DFIR and SOC investigations**.

Well done for sticking through it — this was not an easy one.

