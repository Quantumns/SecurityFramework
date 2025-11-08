🧰 SME Security Framework (PowerShell)
Overview

The SecurityFramework is a PowerShell-based automation tool designed for small and medium-sized enterprises (SMEs) to harden Windows systems against common threats.

It applies and audits system configurations according to:

CIS Critical Security Controls v8

Microsoft Security Baselines

Each module corresponds to a security area such as:

Account policies

Firewall and network rules

Defender protections

Update and patch management

Logging and auditing

BitLocker encryption

Application and browser hardening

System hygiene

The tool can run in two modes:

Audit → checks compliance and logs results (read-only)

Enforce → applies secure baseline settings automatically

⚙️ Requirements

Windows 10 or 11 (Pro edition recommended)

PowerShell 5.1 or later

Administrator rights (required only for “Enforce” mode)

Internet access optional (used for baseline updates)

No external modules are required — everything runs natively on Windows PowerShell.

📁 Project Structure
SecurityFramework/
│
├── Framework.ps1                → main engine that loads and runs modules
├── Start-Framework.ps1          → menu launcher (user interface)
│
├── Config/
│   └── config.json              → general configuration (can be customized)
│
├── Modules/
│   └── Firewall/
│       └── Firewall.psm1        → example security module
│   └── (future modules go here)
│
└── Logs/
    └── run-*.json               → audit/enforce results saved automatically

🚀 Quick Start
1️⃣ Launch the menu

Open Windows PowerShell as Administrator, then run:

cd "C:\Users\Quantum\Documents\SecurityFramework"
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-Framework.ps1

2️⃣ Use the menu

When the menu appears:

=== Security Framework Menu ===
1) Audit ALL modules
2) Enforce ALL modules
3) Run ONE module
4) Show LAST RUN summary
5) Exit

Option 1 — Audit ALL

Checks all modules and creates a compliance log in Logs\.

Option 2 — Enforce ALL

Applies secure baselines for all modules.
🟢 Requires admin rights — the script will elevate automatically.

Option 3 — Run ONE module

Lets you select a specific module (e.g., Firewall) and choose Audit or Enforce.

Option 4 — Show LAST RUN summary

Displays the latest results and an overall Hardening Score, similar to HardeningKitty:

Outcome	Points	Meaning
Compliant / Already Compliant	4	Passed
Applied	2	Fixed minor issue
Partial	1	Needs review
Non-Compliant / Failed	0	High-risk finding

Score formula:
(Points / MaxPoints) × 5 + 1

Example:
If your system gets 82 points out of 100 → (82 / 100 × 5) + 1 = 5.1 → “Well done / Good”

Option 5 — Exit

Closes the launcher safely.

🧾 Example Run
=== Security Framework Menu ===
1) Audit ALL modules
2) Enforce ALL modules
3) Run ONE module
4) Show LAST RUN summary
5) Exit

Select option (1-5): 3

Available modules:
1) Firewall
Pick module number: 1
Run mode for 'Firewall' (Audit/Enforce): Audit
[RUN] Audit [Firewall]
[INFO] Loading module: Firewall
[INFO] Running Firewall in Audit mode
[INFO] Run log written: Logs\run-20251108-121245_ENES-PC.json


Then check results with option 4 or open the JSON log in Logs\.

🧩 Adding New Modules

To expand the framework:

Create a new folder under Modules, e.g.:

Modules\Updates\


Inside it, create a PowerShell module file:

Updates.psm1


The module must export a function called:

function Invoke-Updates { ... }
Export-ModuleMember -Function Invoke-Updates


It should return a PowerShell object:

[pscustomobject]@{
    module  = "Updates"
    outcome = "Compliant"
    details = @("All patches installed")
    cisMappings = @("7.3")
    msMappings  = @("WindowsBaseline:Updates")
}


When you relaunch the menu, the new module will appear automatically.

🪪 Logging & Reporting

Every run (Audit or Enforce) creates a log in Logs\:

run-YYYYMMDD-HHMMSS_HOST.json


Each module’s outcome is marked as:

Compliant

Already Compliant

Applied

Partial

Non-Compliant

Skipped (if controlled by policy)

Failed

You can import logs into Excel or Power BI for analysis.

🛡️ Recommended Usage

First run: Audit All → understand your current baseline.

Second run: Enforce All → apply configurations.

Third run: Audit All → confirm compliance and export logs.

For ongoing monitoring, schedule the Audit command weekly via Task Scheduler.

🧠 Tips

Always run Enforce as Administrator.

Modules are idempotent — safe to run multiple times.

Skipped means a Group Policy or baseline already controls that setting.

Back up registry and configs before using new modules.