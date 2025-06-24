# cha-udit-FirewallRuleAnalyzer
Analyzes firewall rules (iptables, firewalld, or Windows Firewall) to identify overly permissive or redundant rules. Uses `iptables-save`, `firewall-cmd --list-all`, or `netsh advfirewall show allprofiles` and processes the output using regular expressions or structured data libraries like `json` when available. - Focused on Utility for auditing system and application configurations against established security baselines (e.g., CIS benchmarks). Supports YAML and JSON configuration files.  Identifies deviations from the security baseline and provides remediation recommendations, helping to reduce attack surface and improve security posture.

## Install
`git clone https://github.com/ShadowGuardAI/cha-udit-firewallruleanalyzer`

## Usage
`./cha-udit-firewallruleanalyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: The type of firewall to analyze.
- `-c`: No description provided
- `-o`: Path to the output file for the report.

## License
Copyright (c) ShadowGuardAI
