"""Framework controls as data: each control names the period check that evidences it and the asset scope it applies to.

Control wording is paraphrased. Mapping a check to a control is an engineering aid, not an audit opinion.
"""

CONTROLS = [
    # framework, control id, short title, check, scope, check options
    ("PCI DSS v4.0", "11.4.2/11.4.3", "Pentest periodically and after any significant change", "after_change", "pci", {}),
    ("PCI DSS v4.0", "11.4.4", "Exploitable findings corrected and retested", "retest", "pci", {}),
    ("PCI DSS v4.0", "6.3.3", "Critical patches installed within one month", "patch", "pci", {}),
    ("PCI DSS v4.0", "8.6.2", "No hard-coded passwords for system/application accounts", "secrets", "pci", {}),
    ("PCI DSS v4.0", "6.2.3", "Bespoke software reviewed before release", "pr_review", "pci", {}),
    ("PCI DSS v4.0", "2.2", "System components configured and managed securely", "sla", "pci", {"sources": ["cloud"], "min": "high"}),
    ("ISO 27001:2022", "A.8.8", "Management of technical vulnerabilities", "sla", "in_scope", {"min": "medium"}),
    ("ISO 27001:2022", "A.8.9", "Configuration management", "sla", "in_scope", {"sources": ["cloud"], "min": "high"}),
    ("ISO 27001:2022", "A.8.29", "Security testing in development and acceptance", "pr_review", "in_scope", {}),
    ("ISO 27001:2022", "A.5.17", "Authentication information", "secrets", "in_scope", {}),
    ("SOC 2", "CC7.1", "Detect vulnerabilities and configuration weaknesses", "cadence", "in_scope", {}),
    ("SOC 2", "CC8.1", "Changes are tested", "after_change", "in_scope", {}),
    ("HIPAA", "§164.308(a)(1)(ii)(B)", "Risk management", "sla", "in_scope", {"min": "high"}),
    ("HIPAA", "§164.308(a)(8)", "Periodic technical evaluation", "cadence", "in_scope", {}),
]

SEVERITY = {"low": 0, "medium": 1, "high": 2, "critical": 3}
