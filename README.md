<div align="center">

# 🛡️ SME Security Framework

### Automated Endpoint Hardening & Compliance for Small/Medium Enterprises

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue?style=flat&logo=powershell)
![Platform](https://img.shields.io/badge/Platform-Windows_10%2F11_Pro-blue?style=flat&logo=windows)
![License](https://img.shields.io/badge/License-MIT-green?style=flat)
![Status](https://img.shields.io/badge/Status-Stable-success)

</div>

---

### 📖 Overview

**SME Security Framework** is a modular, PowerShell-based automation tool designed to secure Windows computers in Small and Medium-sized Enterprises (SMEs). 

Unlike complex enterprise tools that require dedicated servers, this framework runs locally on standard laptops and desktops to apply industry-standard security controls (**CIS Benchmarks** & **Microsoft Security Baselines**) automatically.

It bridges the gap between complex security standards and limited IT resources by offering **One-Click Hardening**, **Dual-Layer Safety**, and **Smart Scoring**.

<br>

### ✨ Key Features

* **🚀 One-Click Hardening:** Automatically applies security settings for Firewall, BitLocker, Defender, and more.
* **🛡️ Dual-Layer Backup:** * **Layer 1:** Creates a native Windows System Restore Point.
    * **Layer 2:** Exports file-based backups of critical Registry keys and Firewall rules to JSON.
* **🧠 Smart Enforcement:** Idempotent modules only apply changes when necessary. 
* **📊 Weighted Scoring:** Uses an advanced algorithm to rate security posture from "Weak" to "Secure & Loaded".
* **🏢 Business Continuity:** Includes configurable exceptions for critical tools (e.g., **TeamViewer** on Port 5938).

<br>

### 🖼️ The Interface

The framework uses a menu-driven interface for ease of use.

**Main Menu:**
<br>
![Main Menu Screenshot](https://github.com/Quantumns/SecurityFramework/blob/ca759a0506ac4500a4032e24b9f9747dc033d87b/Menu.jpeg)
<br>
*Select Audit to check status or Enforce to apply fixes.*

<br>

**Module Selection:**
<br>
![Module Selection Screenshot](https://github.com/Quantumns/SecurityFramework/blob/ca759a0506ac4500a4032e24b9f9747dc033d87b/Module%20Selection.jpeg)
<br>
*Target specific areas like Firewall or BitLocker individually.*

<br>

**Logs & Reports:**
<br>
![Logs Menu Screenshot](https://github.com/Quantumns/SecurityFramework/blob/ca759a0506ac4500a4032e24b9f9747dc033d87b/Logs%20%26%20Reports.jpeg)
<br>
*Instantly review past compliance logs, monitor live firewall activity, and verify system rollback status.*

<br>

### ⚙️ How To Run

1.  **Download** the repository to your target machine.
2.  **Unblock** the file (PowerShell security requirement):
    ```powershell
    Unblock-File .\Start-Framework.ps1
    ```
3.  **Run** the menu launcher:
    ```powershell
    .\Start-Framework.ps1
    ```

> **Note:** For full enforcement features, run PowerShell as **Administrator**. The tool will automatically prompt for elevation if required.

<br>

### 🛠️ Modules Included

| Module | Description | CIS Mapping |
| :--- | :--- | :--- |
| **Accounts** | Enforces password complexity, lockout policies, and disables Guest. | 5.2, 5.3 |
| **Services** | Disables risky legacy protocols like SMBv1 and Telnet. | 4.8 |
| **Defender** | Enables Real-time Monitoring, Cloud Protection (MAPS), and PUA blocks. | 10.1, 10.2 |
| **Firewall** | Enforces "Default Deny" inbound rules and blocks high-risk ports (445, 23). | 4.4, 4.5 |
| **Updates** | Configures automatic Windows Update installation schedules. | 7.1, 7.3 |
| **Logging** | Enables advanced auditing (Process Creation, Logon) for forensic analysis. | 8.2, 8.5 |
| **BitLocker** | Encrypts the system drive using XTS-AES 256 (if TPM is present). | 3.6, 3.11 |
| **Hardening** | Blocks Office Macros from internet and enables Attack Surface Reduction (ASR). | 9.2, 16.7 |
| **Hygiene** | Removes bloatware (e.g., Xbox, Solitaire) and cleans temporary files. | 4.7, 4.10 |

<br>

### 📈 Scoring & Rating System

The framework calculates a **Security Score** based on the number of compliant modules. It awards full points for modules that were successfully fixed ("Applied") during the run.

| Score | Rating (Casual) | Rating (Professional) |
| :---: | :--- | :--- |
| **6.0** | 🚀 **! Secure & Loaded !** | Excellent |
| **5.0** | 🛡️ **Great Job** | Strong |
| **4.0** | ✅ **Does the job** | Sufficient |
| **3.0** | ⚠️ **You should do better** | Insufficient |
| **2.0** | 🚧 **Weak** | Insufficient |
| **1.0** | ❌ **Bogus** | Insufficient |

*Formula: `(Points Achieved / Maximum Points) * 5 + 1`*

<br>

### 🔧 Configuration

You can customize settings in `Config\Config.json` to fit your business needs.

**Example: Allow specific apps through Firewall**
```json
"firewall": {
  "appRules": [
    {
      "name": "TeamViewer",
      "path": "C:\\Program Files\\TeamViewer\\TeamViewer.exe",
      "port": "5938",
      "enabled": true
    }
  ]
}

⚠️ Disclaimer
This tool modifies system configurations. While it includes a Dual-Layer Backup mechanism, always test in a safe environment (VM) before deploying to production systems.

Developed for the Bachelor Thesis: "Securing Computers in Small-Sized Enterprises"

Vistula University - 2025
