SME Security Framework

A PowerShell-based automation tool designed to secure Windows computers in Small and Medium-sized Enterprises (SMEs). It applies industry-standard security controls (CIS & Microsoft Baselines) automatically.

Key Features

One-Click Hardening: Automatically applies security settings.

Safety First: Creates a Windows System Restore Point before making any changes.

Audit Mode: Checks your system security without modifying it.

Modular: Includes specific modules for Firewall, BitLocker, Updates, and more.

No Dependencies: Works on standard Windows 10/11 using built-in PowerShell.

Included Modules

Accounts: Enforces password policies and disables Guest account.

Services: Disables risky protocols like SMBv1 and Telnet.

Defender: Enables Antivirus Real-time monitoring and Cloud protection.

Firewall: Blocks inbound traffic and high-risk ports.

Updates: Configures automatic Windows Updates.

Logging: Enables advanced auditing for forensic analysis.

BitLocker: Encrypts the hard drive (if TPM is present).

Hardening: Blocks Office Macros and malicious scripts.

Hygiene: Removes bloatware and cleans temporary files.

How to Use

Right-click Start-Framework.ps1.

Select "Run with PowerShell".

Choose an option from the menu:

Audit: To see what is wrong.

Enforce: To fix it (Requires Admin).

Configuration

You can change settings (like allowed ports or password length) in Config\Config.json.

Disclaimer

This tool modifies system settings. Always test in a safe environment first. The tool automatically attempts to create a Restore Point before enforcement.