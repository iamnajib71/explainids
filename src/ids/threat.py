"""Candidate MITRE ATT&CK context, severity and response guidance for predicted classes.

Mappings are *candidates* for analyst confirmation: flow features show network symptoms, not
adversary intent, so a class may fit several techniques. Unknown classes are "unmapped".
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

ATTACK_URL = "https://attack.mitre.org/techniques/{}/"


@dataclass(frozen=True)
class ThreatContext:
    technique_id: str | None
    technique: str
    tactic: str
    severity: str
    guidance: str

    def to_dict(self) -> dict:
        d = asdict(self)
        d["url"] = ATTACK_URL.format(self.technique_id.replace(".", "/")) if self.technique_id else None
        return d


_BRUTE = ("T1110", "Brute Force", "Credential Access", "High",
          "Review authentication logs for the target; lock or rate-limit repeated failures and enforce MFA.")
_DOS_ENDPOINT = ("T1499", "Endpoint Denial of Service", "Impact", "High",
                 "Check web server load; enable rate limiting or upstream filtering for the source.")

MAPPING: dict[str, ThreatContext] = {
    "PortScan": ThreatContext("T1046", "Network Service Discovery", "Discovery", "Medium",
                              "Confirm whether the scan source is authorised; restrict exposed services."),
    "FTP-BruteForce": ThreatContext(*_BRUTE),
    "SSH-BruteForce": ThreatContext(*_BRUTE),
    "Web-BruteForce": ThreatContext(*_BRUTE),
    "Web-SQLInjection": ThreatContext("T1190", "Exploit Public-Facing Application", "Initial Access", "Critical",
                                      "Inspect web application logs and inputs; patch and validate input handling."),
    "DoS-Slowloris": ThreatContext(*_DOS_ENDPOINT),
    "DoS-SlowHTTPTest": ThreatContext(*_DOS_ENDPOINT),
    "DoS-Hulk": ThreatContext(*_DOS_ENDPOINT),
    "DoS-GoldenEye": ThreatContext(*_DOS_ENDPOINT),
    "DDoS-HTTP": ThreatContext(*_DOS_ENDPOINT),
    "DDoS-UDP": ThreatContext("T1498", "Network Denial of Service", "Impact", "High",
                              "Contact the upstream provider about volumetric filtering; monitor link saturation."),
    "Bot": ThreatContext("T1071", "Application Layer Protocol", "Command and Control", "High",
                         "Isolate the host and check for command-and-control beaconing."),
}
UNMAPPED = ThreatContext(None, "unmapped", "-", "Medium", "Analyst review required: no candidate technique.")
ANOMALY = ThreatContext(None, "unmapped (statistical outlier)", "-", "Medium",
                        "Unusual traffic with no matching known class: review the flow and its host.")


def context_for(label: str, is_outlier: bool = False) -> ThreatContext:
    if label == "BENIGN":
        return ANOMALY if is_outlier else ThreatContext(None, "none", "-", "Info", "No action.")
    return MAPPING.get(label, UNMAPPED)
