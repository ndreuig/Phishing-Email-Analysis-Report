# PhishStrike Lab — Phishing Email Analysis Report
 
**Date:** December 9, 2022  
**Lab:** PhishStrike  
**Severity:** Critical  
 
---
 
## 1. Executive Summary
 
A phishing email impersonating a commercial purchase receipt was delivered on December 9, 2022. The email was spoofed from a compromised Colombian university account (uptc.edu.co), with all authentication checks (SPF, DKIM, DMARC) failing. The email contained a malicious link (http://107.175.247.199/loader/install.exe) which was confirmed by URLhaus as an active malware distribution point serving three malware families — **CoinMiner**, **AsyncRAT**, and **BitRAT**. Sandbox analysis of the retrieved payloads revealed capabilities including persistent remote access, cryptocurrency mining, and C2 communication via Telegram. All three payloads share common infrastructure, suggesting a single threat actor behind the campaign.
 
---
 
## 2. Email Analysis
 
### 2.1 Social Engineering Lure
 
The email posed as a **Commercial Purchase Receipt**, claiming a purchase of $625,000 pesos (Reference No. 00034959) had been completed. The recipient was urged to click a link to view the invoice document, accompanied by an access code (`8657`) to add legitimacy.
 
The email was signed with the name and title of a real educator (*Erika Johana López Valiente, Magister in Education, LEB Teacher - FESAD*), suggesting the sender's account was compromised and used to add credibility to the lure.
 
> **Screenshot:** `phish-03-malicious-url.PNG`
 
### 2.2 Email Header Analysis
 
| Field | Value |
|-------|-------|
| Return-Path | `erikajohana.lopez@uptc.edu.co` |
| Sending IP | `18.208.22.104` |
| SPF Result | **Softfail** — `uptc.edu.co` discourages use of this IP |
| DKIM Result | **Fail** — no key for signature |
| DMARC Result | **None** — no action taken |
| ARC Result | **Fail** |
| Auth-Source | `BL6PEPF0001AB51.namprd04.prod.outlook.com` |
| Organization-AuthAs | **Anonymous** |
 
All authentication mechanisms (SPF, DKIM, DMARC) failed or returned no action, confirming the email was spoofed. The sender appeared to use a compromised `uptc.edu.co` account routed through an unauthorized IP.
 
> **Screenshots:** `phish-01-email-header-analysis.PNG`, `phish-01-return-path-analysis.PNG`
 
---
 
## 3. Malicious URL Analysis
 
The email contained the following link presented as an invoice download:
 
```
http://107.175.247.199/loader/install.exe
```
 
This URL was queried against the **URLhaus** malware database, which confirmed it as an active malware distribution point. The host `107.175.247.199` served three distinct malware payloads between October and December 2022.
 
| First Seen | File Type | SHA256 | Malware Family |
|------------|-----------|--------|----------------|
| 2022-10-22 | EXE | `453fb1c4b3b48361fa8a67dcedf1eaec39449cb5a146a7770c63d1dc0d7562f0` | CoinMiner |
| 2022-10-25 | EXE | `5ca468704e7ccb8e1b37c0f7595c54df4e2f4035345b6e442e8bd4e11c58f791` | AsyncRAT |
| 2022-10-26 | EXE | `bf7628695c2df7a3020034a065397592a1f8850e59f9a448b555bc1c8c639539` | BitRAT |
 
- **URL Status:** Offline (taken down 2022-12-12)
- **Takedown Time:** 1 month, 20 days, 18 hours, 19 minutes
- **Reported by:** abuse.ch
- **Abuse complaint sent to:** `abuse@hudsonvalleyhost.com`
> **Screenshots:** `phish-04-payloads.PNG`, `phish-04-urlhaus1.PNG`
 
---
 
## 4. Payload Analysis
 
All three payloads were delivered from the same C2 infrastructure and share overlapping persistence mechanisms and network patterns, indicating a common loader framework controlled by a single threat actor.
 
---
 
### 4.1 Payload 1 — CoinMiner
 
**SHA256:** `453fb1c4b3b48361fa8a67dcedf1eaec39449cb5a146a7770c63d1dc0d7562f0`  
**MD5:** `9628AFC9116DB52960422B598996D19F`  
**SHA1:** `6432CC7A73276E9100D5BE8DE087E4E1FEF628BE`
 
#### Persistence — Registry Run Keys
 
| Run Key Name | Executable Path |
|-------------|-----------------|
| `Fsaxd` | `C:\Users\Admin\AppData\Roaming\Fdqudm\Fsaxd.exe` |
| `svcsvc` | `C:\Users\Admin\AppData\Local\svcsvc\svcsvc.exe` |
 
Both keys are set under `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, ensuring execution on every user login.
 
> **Screenshot:** `phish-06-coinminer-runkeys.PNG`
 
#### Network Activity
 
| Type | IOC | Notes |
|------|-----|-------|
| DNS | `ripley.studio` | Loader staging domain |
| GET | `http://ripley.studio/loader/uploads/Qanjttrbv.jpeg` | Disguised payload (fake JPEG) |
| GET | `http://107.175.247.199/loader/server.exe` | Second-stage executable download |
| DNS | `gh9st.mywire.org` | Dynamic DNS — CoinMiner C2/mining pool |
 
> **Screenshot:** `phish-07-coinminer-network.PNG`
 
#### Process Behavior — Sandbox Evasion
 
The malware spawns PowerShell with a base64-encoded command:
 
```
powershell.exe -enc UwB0AGEAcgB0AC0AUwBsAGUAZQBwACAALQBTAGUAYwBvAG4AZABzACAANQAwAA==
```
 
Decoded:
```powershell
Start-Sleep -Seconds 50
```
 
This is a **sandbox evasion technique** — the malware delays execution by 50 seconds to outlast automated sandbox timeouts before performing malicious activity.
 
> **Screenshot:** `phish-08-coinminer-powershell.PNG`
 
#### Dropped Files
 
| Path | Type |
|------|------|
| `C:\Users\user\AppData\Roaming\Fdqudm\Fsaxd.exe` | PE32 .NET executable — persistence copy |
| `C:\Users\user\AppData\Local\Microsoft\Windows\INetCache\IE\OTUW0Q90\server[1].exe` | PE32 .NET executable — second-stage payload |
 
> **Screenshot:** `phish-09-coinminer-droppedfiles.PNG`
 
---
 
### 4.2 Payload 2 — BitRAT
 
**SHA256:** `bf7628695c2df7a3020034a065397592a1f8850e59f9a448b555bc1c8c639539`
 
#### Persistence — Registry Run Keys
 
| Run Key Name | Executable Path |
|-------------|-----------------|
| `Jzwvix` | `C:\Users\Admin\AppData\Roaming\Ozndcoodb\Jzwvix.exe` |
| `PUTTY` | `C:\Users\Admin\AppData\Roaming\PUTTY.EXE` |
| `svcsvc` | `C:\Users\Admin\AppData\Local\svcsvc\svcsvc.exe` |
 
The use of `PUTTY` as a run key name is a **masquerading technique**, mimicking the legitimate PuTTY SSH client to avoid suspicion.
 
> **Screenshot:** `phish-10-bitrat-runkeys.PNG`
 
#### Network Activity
 
| Type | IOC | Notes |
|------|-----|-------|
| DNS | `ripley.studio` | Loader staging domain |
| GET | `http://ripley.studio/loader/uploads/Hjvnp.png` | Disguised payload (fake PNG) |
| GET | `http://107.175.247.199/loader/server.exe` | Second-stage executable download |
| DNS | `gh9st.mywire.org` | Dynamic DNS — BitRAT C2 |
 
> **Screenshot:** `phish-11-bitrat-network.PNG`
 
#### Dropped Files
 
| Path | Type |
|------|------|
| `C:\Users\user\AppData\Roaming\Ozndcoodb\Jzwvix.exe` | PE32 .NET executable — persistence copy |
| `C:\Users\user\AppData\Local\Microsoft\Windows\INetCache\IE\B87Z87FM\server[1].exe` | PE32 .NET executable — second-stage payload |
 
> **Screenshot:** `phish-12-bitrat-droppedfiles.PNG`
 
---
 
### 4.3 Payload 3 — AsyncRAT
 
**SHA256:** `5ca468704e7ccb8e1b37c0f7595c54df4e2f4035345b6e442e8bd4e11c58f791`
 
#### Persistence — Registry Run Keys
 
| Run Key Name | Executable Path |
|-------------|-----------------|
| `Kjcrksvp` | `C:\Users\Admin\AppData\Roaming\Vlevqbxxsx\Kjcrksvp.exe` |
| `Fsaxd` | `C:\Users\Admin\AppData\Roaming\Fdqudm\Fsaxd.exe` |
| `svcsvc` | `C:\Users\Admin\AppData\Local\svcsvc\svcsvc.exe` |
 
> **Screenshot:** `phish-13-asyncrat-runkeys.PNG`
 
#### Network Activity
 
| Type | IOC | Notes |
|------|-----|-------|
| DNS | `ripley.studio` | Loader staging domain |
| GET | `http://ripley.studio/loader/uploads/Zcpbmqlst.bmp` | Disguised payload (fake BMP) |
| GET | `http://107.175.247.199/loader/server.exe` | Second-stage executable download |
| DNS | `gh9st.mywire.org` | Dynamic DNS — AsyncRAT C2 |
| DNS | `api.telegram.org` | Telegram C2 communication |
| GET | `https://api.telegram.org/bot5610920260:AAHF8huJMzSwUso7...` | **Telegram Bot C2** — repeated beaconing |
| DNS | `www.xenarmor.com` | License validation domain |
| GET | `http://www.xenarmor.com/xen-check-portable-license.php?key=...` | AsyncRAT license check (cracked RAT tool) |
 
The **Telegram Bot C2** (`bot5610920260`) is a notable finding. The malware uses the Telegram Bot API as a covert C2 channel, repeatedly sending GET requests to exfiltrate data or receive commands. This technique abuses a legitimate service to blend in with normal HTTPS traffic.
 
The `xenarmor.com` license check suggests the AsyncRAT variant used here may be based on a commercial or cracked RAT builder.
 
> **Screenshot:** `phish-14-asyncrat-network.PNG`
 
#### Dropped Files
 
| Path | Type |
|------|------|
| `C:\Users\user\AppData\Roaming\Vlevqbxxsx\Kjcrksvp.exe` | PE32 .NET executable — persistence copy |
| `C:\Users\user\AppData\Local\Microsoft\Windows\INetCache\IE\9QTQHWWN\server[1].exe` | PE32 .NET executable — second-stage payload |
 
> **Screenshot:** `phish-15-asyncrat-droppedfiles.PNG`
 
---
 
---
 
## 5. Indicators of Compromise (IOCs)
 
### Network IOCs
 
| Type | Value | Associated Malware |
|------|-------|--------------------|
| IP | `107.175.247.199` | All payloads |
| Domain | `ripley.studio` | All payloads |
| Domain | `gh9st.mywire.org` | CoinMiner, BitRAT |
| Domain | `api.telegram.org` | AsyncRAT |
| Domain | `www.xenarmor.com` | AsyncRAT |
| URL | `http://107.175.247.199/loader/install.exe` | Initial lure |
| URL | `http://107.175.247.199/loader/server.exe` | Second-stage |
| URL | `http://ripley.studio/loader/uploads/Qanjttrbv.jpeg` | CoinMiner |
| URL | `http://ripley.studio/loader/uploads/Hjvnp.png` | BitRAT |
| URL | `http://ripley.studio/loader/uploads/Zcpbmqlst.bmp` | AsyncRAT |
| Telegram Bot ID | `5610920260` | AsyncRAT C2 |
 
### File IOCs
 
| SHA256 | Family | Filename |
|--------|--------|--------|
| `453fb1c4b3b48361fa8a67dcedf1eaec39449cb5a146a7770c63d1dc0d7562f0` | CoinMiner | Fsaxd.exe |
| `5ca468704e7ccb8e1b37c0f7595c54df4e2f4035345b6e442e8bd4e11c58f791` | AsyncRAT | Kjcrksvp.exe |
| `bf7628695c2df7a3020034a065397592a1f8850e59f9a448b555bc1c8c639539` | BitRAT | Jzwvix.exe |
| `92A433340DD32CB379159432FBC26A6F2CA495EF97C31F7FD333913CED03D773` | CoinMiner — server[1].exe | server[1].exe |
| `92A433340DD32CB379159432FBC26A6F2CA495EF97C31F7FD333913CED03D773` | AsyncRat — server[1].exe | server[1].exe |
| `02DB00CA3D50065B6C10C027A64066D00D4A1CD8DBED0B77CE414A64258406F5` | BitRat — server[1].exe | server[1].exe |
 
### Email IOCs
 
| Type | Value |
|------|-------|
| Sender | `erikajohana.lopez@uptc.edu.co` |
| Sending IP | `18.208.22.104` |
 
### Persistence IOCs (Registry)
 
| Run Key | Path |
|---------|------|
| `Fsaxd` | `AppData\Roaming\Fdqudm\Fsaxd.exe` |
| `svcsvc` | `AppData\Local\svcsvc\svcsvc.exe` |
| `Jzwvix` | `AppData\Roaming\Ozndcoodb\Jzwvix.exe` |
| `PUTTY` | `AppData\Roaming\PUTTY.EXE` |
| `Kjcrksvp` | `AppData\Roaming\Vlevqbxxsx\Kjcrksvp.exe` |
 
---
  
---
 
## 6. Key Findings
 
1. **Single threat actor infrastructure** — All three malware families share the same loader host (`107.175.247.199`), staging domain (`ripley.studio`), and secondary C2 (`gh9st.mywire.org`), pointing to a single coordinated campaign.
2. **Telegram Bot C2 (AsyncRAT)** — The use of `api.telegram.org` as a C2 channel (Bot ID: `5610920260`) is a notable evasion technique, abusing a trusted platform to blend malicious traffic with legitimate HTTPS communications.
3. **Consistent disguised payload delivery** — Each malware variant downloaded a fake image file (`.jpeg`, `.png`, `.bmp`) from `ripley.studio` before fetching the real executable, suggesting a shared loader framework.
4. **Shared persistence component** — The `svcsvc.exe` run key appears across all three payloads, suggesting it functions as a shared persistence or watchdog component.
5. **Compromised sender account** — The use of a real educator's email account and identity (`uptc.edu.co`) increased the lure's credibility and bypassed basic sender reputation checks.
