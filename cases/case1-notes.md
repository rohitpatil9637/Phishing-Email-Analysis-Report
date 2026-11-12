# Case 1 Notes

## Case Information

| Field | Value |
| --- | --- |
| Source file | `samples/case1.eml` |
| Reported | Not provided |
| Recipient | `phishing@pot` |
| Received | 18 May 2026, 21:18:26–21:18:32 UTC (18 May 2026, 14:18:26–14:18:32 PDT) |
| Subject | `Message Content Casinova $3,000 bonus + 350 FS` |

## 1. Read: Sender Claim, Request, and Urgency

The email presents itself as **“💰 Casinova Bonus 💰”** and advertises a **$3,000 bonus plus 350 free spins**. It is an unsolicited gambling promotion designed to encourage the recipient to follow embedded links. No explicit password-reset, payment, credential-entry, or urgent business request is present in the extracted content.

## 2. Headers

| Header / control | Observed value | Assessment |
| --- | --- | --- |
| From | `💰Casinova Bonus💰 <gray.miller@entreprise123excv12.onmicrosoft.com>` | Display name is promotional; sender domain is unrelated to the advertised Casinova brand. |
| Reply-To | Not present | No separate reply address observed. |
| Return-Path | `gray.miller@entreprise123excv12.onmicrosoft.com` | Matches the From address. |
| SPF | Fail | `209.85.218.68` was not authorized to send for `entreprise123excv12.onmicrosoft.com`. |
| DKIM | Pass | Signature verified for `entreprise123excv12-onmicrosoft-com.20251104.gappssmtp.com`. This does not validate the advertised Casinova identity. |
| DMARC | None | No DMARC policy/alignment result was present for `entreprise123excv12.onmicrosoft.com`. |
| Message-ID | `<CACN0yYL3uqNapvVbVQw=1=4Q4Spx-L21axqi8NR2hOFDLuw-qg@mail.gmail.com>` | Gmail-generated Message-ID. |

## 3. Sender: Domain and Origin

| Check | Finding |
| --- | --- |
| Sender domain | `entreprise123excv12.onmicrosoft.com` |
| Look-alike assessment | Not a look-alike of the advertised “Casinova” brand; it is an unrelated Microsoft 365 tenant subdomain. |
| Domain age | Not assessed from the supplied evidence. Check registration/tenant history if needed. |
| Originating IP | `209.85.218.68` (`mail-ej1-f68.google.com`) |
| IP reputation | Not assessed from the supplied evidence. The IP is a Google mail host; reputation alone would not establish message legitimacy. |

## 4. Links

Six embedded links were extracted. They all use the domain `woondsplay[.]com` and appear to be unique tracking URLs. The message body contained three images and approximately 216,067 characters of visible text.

| # | Defanged URL |
| --- | --- |
| 1 | `hxxp://woondsplay[.]com/rd/5yeHvk22651pblO702efbyuoeooi205XDLFBRISDCQDQTK164627XRAN1090539B4` |
| 2 | `hxxps://woondsplay[.]com/4PGoJB22651XvRj702fmhnvlcosa205IWQSJJZBOOXCSWL164627FEKC1090539t4` |
| 3 | `hxxps://woondsplay[.]com/4UjAFH22651yGry702okcktlpjfp205HSCOCIRKCVWQPES164627JKNZ1090539E4` |
| 4 | `hxxps://woondsplay[.]com/4XTZqA22651DDOT702haqpwxcrpb205GSFRBFUBJQFAOVQ164627AMWB1090539u4` |
| 5 | `hxxps://woondsplay[.]com/4msyTY22651eQVS702hmrzbnwakh205AVSSCVCIXOGACXA164627ALGK1090539i4` |
| 6 | `hxxps://woondsplay[.]com/4vGfSn22651bDyC702nhhwkbkodm205GRSQIQGXVZWATJN164627INBQ1090539q4` |

## 5. Files and Other Content

| Item | Finding |
| --- | --- |
| Attachments | None |
| File name / type / SHA-256 | Not applicable |
| VirusTotal result | Not applicable for attachments; URL/domain reputation not supplied |
| Images | Three images in the email body |
| QR codes | Not reported; inspect body images if QR-based redirection is suspected |
| Password-protected files | None observed |

## 6. Verdict

**Verdict: Spam / unsolicited gambling promotion — High confidence.**

## 7. Actions

- [ ] Block `woondsplay[.]com` and the listed URLs in the email and web-security controls, subject to organizational policy.
- [ ] Block or quarantine mail from `entreprise123excv12.onmicrosoft.com` if it has no approved business use.
- [ ] Delete or quarantine matching messages across mailboxes using sender, subject, Message-ID, and URLs.
- [ ] Check proxy/DNS and email telemetry for clicks to `woondsplay[.]com`.
- [ ] Notify recipients not to interact with the promotion and to report similar messages.
- [ ] Reset passwords only if investigation finds credential submission or account compromise.
- [ ] Record URL/domain reputation and landing-page findings before case closure.

## Indicators of Compromise

| Type | Value (defanged) | Note |
| --- | --- | --- |
| Sender | `gray.miller@entreprise123excv12.onmicrosoft.com` | From and Return-Path address |
| Domain | `entreprise123excv12.onmicrosoft.com` | Sender tenant subdomain |
| Domain | `woondsplay[.]com` | Embedded-link domain |
| IP | `209[.]85[.]218[.]68` | SMTP host observed in Received chain |
| Message-ID | `CACN0yYL3uqNapvVbVQw=1=4Q4Spx-L21axqi8NR2hOFDLuw-qg@mail[.]gmail[.]com` | Message identifier |
