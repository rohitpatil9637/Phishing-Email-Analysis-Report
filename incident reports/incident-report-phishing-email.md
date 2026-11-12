# Phishing Email Incident Report

| Field | Value |
| --- | --- |
| Case ID | `PH-2026-001 case1.eml` |
| Status | Contained |
| Severity | High |
| Verdict | Malicious — credential phishing with a malicious attachment link   |

## Summary

An email titled **“AMessage Content Casinova $3,000 bonus + 350 FS”** The message contained a malicious link. 

## Details

| Field | Value |
| --- | --- |
| Received |  18 May 2026, 14:18 IST |
| Visible sender | `💰Casinova Bonus💰` |
| Actual sender domain | `gray.miller@entreprise123excv12.onmicrosoft.com` |
| Recipient | `phishing@pot` |
| Subject | `Message Content Casinova $3,000 bonus + 350 FS` |

## Evidence

- SPF: **fail**; DKIM: **pass**; DMARC: **none** for `header.From: 💰Casinova Bonus💰 <gray.miller@entreprise123excv12.onmicrosoft.com>`.
- `Reply-To` and `Return-Path`  `gray.miller@entreprise123excv12.onmicrosoft.com`.
- Originating IP: `209.85.218.68`
- The message body is a single clickable image linking to `hxxp://woondsplay[.]com/rd/5yeHvk22651pblO702efbyuoeooi205XDLFBRISDCQDQTK164627XRAN1090539B4`.
- An `urlscan.io` screenshot shows a Malicious
- No any Attachment

## Analysis

This is a **true positive** phishing email. The strongest indicators are the failed DMARC alignment, the look-alike sender and landing-page domain. Message Content Casinova $3,000 bonus + 350 FS further support a malicious assessment. |

## Indicators of Compromise

| Type | Value (defanged) | Note |
| --- | --- | --- |
| Domain | `gray.miller@entreprise123excv12.onmicrosoft.com` | Look-alike of `microsoft.com`. |
| URL | `hxxp://woondsplay[.]com/rd/5yeHvk22651pblO702efbyuoeooi205XDLFBRISDCQDQTK164627XRAN1090539B4` | Fake login page. |
| IP | `209.85.218.68` | Origin mail server. |
| SHA-256 | `f83ba128155b172ddc03a84340c7a728a7f3bc3af7d03d6ffc4180893a61df3d` | `case1.eml` |
| Sender | `-` | Reply-To address. |

## MITRE ATT&CK Mapping

| Technique | Use in this case |
| --- | --- |
| [T1566.002 — Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) | The message directs the recipient to a credential-harvesting page. |
|  |
| [T1204.001 — Malicious Link](https://attack.mitre.org/techniques/T1204/001/) | A recipient interaction with the link could initiate compromise. |
| [T1656 — Impersonation](https://attack.mitre.org/techniques/T1656/) | The message impersonates Microsoft. |

## Actions Taken

- Deleted the email from all mailboxes.
- Added the malicious domain and originating IP to the block list.
- Advised the user not to click the link or open the attachment.
- Reviewed email and sign-in logs; no link click or sign-in from the phishing site was found.

## Recommendations

- Enforce a DMARC `reject` policy for company-owned domains.
- Enable external-sender banners and email URL/attachment inspection.
- Require multi-factor authentication, preferably phishing-resistant MFA.
- Provide short phishing-awareness training focused on look-alike domains and urgent requests.
- Alert on newly registered look-alike domains targeting company or commonly impersonated brands.

## Severity Guide

| Level | When to use it |
| --- | --- |
| Low | Spam or phishing that nobody clicked and was blocked automatically. |
| Medium | Phishing delivered to a few users with no interaction. |
| High | A user clicked the link or opened the file, or many users received it. |
| Critical | A password was entered or malware executed, with signs of account takeover or spread. |
