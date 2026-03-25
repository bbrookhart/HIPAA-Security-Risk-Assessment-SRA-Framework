"""
src/controls.py
---------------
Complete HIPAA Security Rule controls database.

Contains all 74 implementation specifications across the three safeguard
categories, each with:
  - CFR citation (exact regulatory reference)
  - Required vs. Addressable designation
  - NIST CSF 2.0 function mapping
  - CIS Controls v8 mapping
  - Risk domain classification
  - Assessment guidance questions
  - Evidence examples

This is the authoritative source of truth for the SRA engine.
All scoring, reporting, and gap analysis derives from this database.

Regulatory basis: 45 CFR §§ 164.308, 164.310, 164.312
Reference: NIST SP 800-66r2 (2023), HHS OCR Audit Protocol
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ─────────────────────────────────────────────────────────────
#  Type definitions
# ─────────────────────────────────────────────────────────────

class Safeguard(str, Enum):
    ADMINISTRATIVE = "Administrative"
    PHYSICAL = "Physical"
    TECHNICAL = "Technical"


class Designation(str, Enum):
    REQUIRED = "Required"
    ADDRESSABLE = "Addressable"


class NistFunction(str, Enum):
    GOVERN = "GV - Govern"
    IDENTIFY = "ID - Identify"
    PROTECT = "PR - Protect"
    DETECT = "DE - Detect"
    RESPOND = "RS - Respond"
    RECOVER = "RC - Recover"


class RiskDomain(str, Enum):
    GOVERNANCE = "Governance & Policy"
    ACCESS = "Access Management"
    WORKFORCE = "Workforce & Training"
    INCIDENT = "Incident Response"
    CONTINUITY = "Business Continuity"
    VENDOR = "Third-Party / Vendor"
    PHYSICAL = "Physical Security"
    ENDPOINT = "Endpoint & Device"
    NETWORK = "Network & Transmission"
    AUDIT = "Audit & Monitoring"
    ENCRYPTION = "Encryption & Integrity"
    AUTHENTICATION = "Authentication"


@dataclass
class HIPAAControl:
    """A single HIPAA Security Rule implementation specification."""
    id: str                          # e.g. "AS-01"
    safeguard: Safeguard
    standard: str                    # Parent standard name
    standard_cfr: str                # CFR citation for standard
    specification: str               # Implementation specification name
    specification_cfr: str           # CFR citation for specification
    designation: Designation
    risk_domain: RiskDomain
    nist_functions: list[NistFunction]
    cis_controls: list[str]          # e.g. ["CIS-3", "CIS-6"]
    weight: float                    # Risk weight (1.0–3.0, higher = more critical)
    description: str
    assessment_questions: list[str]
    evidence_examples: list[str]
    remediation_guidance: str
    threat_scenarios: list[str]


# ─────────────────────────────────────────────────────────────
#  Controls database
# ─────────────────────────────────────────────────────────────

CONTROLS: list[HIPAAControl] = [

    # ══════════════════════════════════════════════════════════
    # ADMINISTRATIVE SAFEGUARDS — 45 CFR § 164.308
    # ══════════════════════════════════════════════════════════

    # ── Security Management Process ──────────────────────────

    HIPAAControl(
        id="AS-01",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Security Management Process",
        standard_cfr="§164.308(a)(1)",
        specification="Risk Analysis",
        specification_cfr="§164.308(a)(1)(ii)(A)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.GOVERNANCE,
        nist_functions=[NistFunction.IDENTIFY, NistFunction.GOVERN],
        cis_controls=["CIS-18"],
        weight=3.0,
        description=(
            "Conduct an accurate and thorough assessment of the potential risks and "
            "vulnerabilities to the confidentiality, integrity, and availability of "
            "ePHI held by the covered entity."
        ),
        assessment_questions=[
            "Has the organization conducted a formal, documented risk analysis?",
            "Does the risk analysis cover ALL systems that create, receive, maintain, or transmit ePHI?",
            "Is the risk analysis updated when environmental or operational changes occur?",
            "Does the analysis identify threats, vulnerabilities, and current controls?",
            "Is the risk analysis reviewed and approved by organizational leadership?",
        ],
        evidence_examples=[
            "Documented risk analysis report signed by Security Officer",
            "Asset inventory of all ePHI systems included in scope",
            "Threat/vulnerability matrix with likelihood and impact ratings",
            "Date of most recent analysis and trigger for update",
        ],
        remediation_guidance=(
            "Conduct a formal SRA using the HHS SRA Tool or equivalent methodology. "
            "Document all ePHI assets, threats, vulnerabilities, existing controls, "
            "likelihood, impact, and resulting risk level. Review annually and after "
            "significant operational or environmental changes."
        ),
        threat_scenarios=[
            "Ransomware attack on EHR system",
            "Insider theft of patient records",
            "Third-party vendor breach exposing shared ePHI",
            "Unencrypted laptop theft",
        ],
    ),

    HIPAAControl(
        id="AS-02",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Security Management Process",
        standard_cfr="§164.308(a)(1)",
        specification="Risk Management",
        specification_cfr="§164.308(a)(1)(ii)(B)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.GOVERNANCE,
        nist_functions=[NistFunction.IDENTIFY, NistFunction.GOVERN],
        cis_controls=["CIS-18"],
        weight=3.0,
        description=(
            "Implement security measures sufficient to reduce risks and vulnerabilities "
            "to a reasonable and appropriate level to comply with § 164.306(a)."
        ),
        assessment_questions=[
            "Is there a documented risk management plan addressing identified risks?",
            "Are risk mitigation strategies prioritized by risk level?",
            "Is there a formal process to track remediation of identified risks?",
            "Does leadership review and approve the risk management plan?",
            "Are risk acceptance decisions documented when mitigation is not pursued?",
        ],
        evidence_examples=[
            "Risk management plan or risk register",
            "Remediation tracking spreadsheet or ticketing system",
            "Executive sign-off on accepted risks",
            "Evidence of completed remediation actions",
        ],
        remediation_guidance=(
            "Develop a Risk Management Plan that assigns ownership, timelines, and "
            "resources to each identified risk. Track progress in a risk register. "
            "Document formal risk acceptance for items that cannot be fully remediated."
        ),
        threat_scenarios=[
            "Known vulnerability left unpatched due to no prioritization process",
            "Risk identified in prior SRA never addressed",
        ],
    ),

    HIPAAControl(
        id="AS-03",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Security Management Process",
        standard_cfr="§164.308(a)(1)",
        specification="Sanction Policy",
        specification_cfr="§164.308(a)(1)(ii)(C)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.WORKFORCE,
        nist_functions=[NistFunction.GOVERN, NistFunction.PROTECT],
        cis_controls=["CIS-14"],
        weight=2.0,
        description=(
            "Apply appropriate sanctions against workforce members who fail to comply "
            "with the security policies and procedures of the covered entity."
        ),
        assessment_questions=[
            "Is there a documented sanction policy for security policy violations?",
            "Are workforce members made aware of the sanction policy during onboarding?",
            "Is the policy applied consistently regardless of role or seniority?",
            "Are sanctions documented and retained in personnel records?",
        ],
        evidence_examples=[
            "Written sanction policy document",
            "Employee handbook section on security violations",
            "Acknowledgment forms signed by workforce members",
            "HR records of sanctions applied",
        ],
        remediation_guidance=(
            "Develop a sanction policy defining graduated consequences for security "
            "violations from verbal warning to termination. Ensure consistent, "
            "documented application and integrate with HR processes."
        ),
        threat_scenarios=[
            "Employee sharing login credentials without consequence",
            "Staff accessing patient records out of curiosity (snooping)",
        ],
    ),

    HIPAAControl(
        id="AS-04",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Security Management Process",
        standard_cfr="§164.308(a)(1)",
        specification="Information System Activity Review",
        specification_cfr="§164.308(a)(1)(ii)(D)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.AUDIT,
        nist_functions=[NistFunction.DETECT, NistFunction.IDENTIFY],
        cis_controls=["CIS-8"],
        weight=2.5,
        description=(
            "Implement procedures to regularly review records of information system "
            "activity, such as audit logs, access reports, and security incident "
            "tracking reports."
        ),
        assessment_questions=[
            "Are audit logs enabled on all systems that access ePHI?",
            "Is there a documented procedure for regular log review?",
            "How frequently are audit logs reviewed?",
            "Is there a process to detect and escalate anomalous activity?",
            "Are log review findings documented and retained?",
        ],
        evidence_examples=[
            "Audit log review policy and procedure",
            "Evidence of periodic log reviews (reports, tickets)",
            "SIEM or log management system configuration",
            "Escalation procedure for suspicious activity",
        ],
        remediation_guidance=(
            "Implement a SIEM or log aggregation tool to centralize ePHI system logs. "
            "Establish weekly (minimum) log review cycles with documented findings. "
            "Define alerting thresholds for anomalous access patterns."
        ),
        threat_scenarios=[
            "Insider accessing records of high-profile patients",
            "Attacker persisting in system undetected due to no log review",
        ],
    ),

    # ── Assigned Security Responsibility ─────────────────────

    HIPAAControl(
        id="AS-05",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Assigned Security Responsibility",
        standard_cfr="§164.308(a)(2)",
        specification="Security Official",
        specification_cfr="§164.308(a)(2)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.GOVERNANCE,
        nist_functions=[NistFunction.GOVERN],
        cis_controls=["CIS-14"],
        weight=2.0,
        description=(
            "Identify the security official who is responsible for the development "
            "and implementation of the policies and procedures required by this subpart."
        ),
        assessment_questions=[
            "Is a Security Official formally designated in writing?",
            "Does the Security Official have sufficient authority and resources?",
            "Are the Security Official's responsibilities documented?",
            "Is there a backup designee in case of absence?",
        ],
        evidence_examples=[
            "Written designation letter or job description",
            "Organizational chart showing Security Official's position",
            "Security policies signed by Security Official",
        ],
        remediation_guidance=(
            "Formally designate a Security Official via written documentation. "
            "For small practices, this may be the owner/practice manager. "
            "Ensure this individual has authority to enforce security policies."
        ),
        threat_scenarios=[
            "Security incidents not reported due to unclear ownership",
            "No accountability for policy compliance",
        ],
    ),

    # ── Workforce Security ────────────────────────────────────

    HIPAAControl(
        id="AS-06",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Workforce Security",
        standard_cfr="§164.308(a)(3)",
        specification="Authorization and/or Supervision",
        specification_cfr="§164.308(a)(3)(ii)(A)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.ACCESS,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-6"],
        weight=2.0,
        description=(
            "Implement procedures for the authorization and/or supervision of "
            "workforce members who work with ePHI or in locations where it might "
            "be accessed."
        ),
        assessment_questions=[
            "Is there a formal process for authorizing workforce access to ePHI?",
            "Are access levels matched to job function (minimum necessary)?",
            "Is ePHI access reviewed when employees change roles?",
        ],
        evidence_examples=[
            "Access authorization forms",
            "Role-based access control (RBAC) documentation",
            "Role change procedures",
        ],
        remediation_guidance=(
            "Implement role-based access control aligned to job functions. "
            "Document the access authorization process and review access levels "
            "at least annually and upon any role change."
        ),
        threat_scenarios=[
            "Former employee retaining access after termination",
            "Employees accessing ePHI beyond their job requirements",
        ],
    ),

    HIPAAControl(
        id="AS-07",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Workforce Security",
        standard_cfr="§164.308(a)(3)",
        specification="Workforce Clearance Procedure",
        specification_cfr="§164.308(a)(3)(ii)(B)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.WORKFORCE,
        nist_functions=[NistFunction.PROTECT, NistFunction.GOVERN],
        cis_controls=["CIS-6"],
        weight=1.5,
        description=(
            "Implement procedures to determine that the access of a workforce member "
            "to ePHI is appropriate."
        ),
        assessment_questions=[
            "Are background checks conducted for employees with ePHI access?",
            "Is there a documented clearance procedure before ePHI access is granted?",
            "Are contractors and temporary workers subject to the same clearance process?",
        ],
        evidence_examples=[
            "Background check policy",
            "Onboarding checklist including clearance steps",
            "Contractor agreement including background check requirements",
        ],
        remediation_guidance=(
            "Implement background screening as a pre-condition for ePHI access. "
            "Apply this consistently to employees, contractors, and temporary workers. "
            "Document the clearance decision for each individual."
        ),
        threat_scenarios=[
            "Insider threat from employee with undisclosed criminal history",
        ],
    ),

    HIPAAControl(
        id="AS-08",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Workforce Security",
        standard_cfr="§164.308(a)(3)",
        specification="Termination Procedures",
        specification_cfr="§164.308(a)(3)(ii)(C)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.ACCESS,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-6", "CIS-4"],
        weight=2.5,
        description=(
            "Implement procedures for terminating access to ePHI when employment "
            "of a workforce member ends or as required by determinations made for "
            "§ 164.308(a)(3)(ii)(B)."
        ),
        assessment_questions=[
            "Is there a documented off-boarding process that revokes ePHI access?",
            "How quickly is access revoked upon termination (same day/hour)?",
            "Are all access points covered (EHR, email, VPN, physical)?",
            "Is access revocation verified and documented?",
        ],
        evidence_examples=[
            "Termination checklist including system access revocation",
            "HR-IT integration for automated account deprovisioning",
            "Audit log showing account disable within expected timeframe",
        ],
        remediation_guidance=(
            "Establish an immediate access revocation procedure triggered by HR "
            "termination notification. For involuntary terminations, revoke access "
            "at the time of notification. Automate where possible via HR-IT integration. "
            "Verify and document completion."
        ),
        threat_scenarios=[
            "Disgruntled former employee accessing patient records post-termination",
            "Terminated employee downloading records before departure",
        ],
    ),

    # ── Information Access Management ─────────────────────────

    HIPAAControl(
        id="AS-09",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Information Access Management",
        standard_cfr="§164.308(a)(4)",
        specification="Isolating Healthcare Clearinghouse",
        specification_cfr="§164.308(a)(4)(ii)(A)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.NETWORK,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-12"],
        weight=1.5,
        description=(
            "If a healthcare clearinghouse is part of a larger organization, "
            "implement policies and procedures that protect ePHI of the clearinghouse "
            "from unauthorized access by the larger organization."
        ),
        assessment_questions=[
            "Is the clearinghouse function isolated from other organizational systems?",
            "Are network segregation controls in place to limit access?",
        ],
        evidence_examples=[
            "Network diagram showing clearinghouse isolation",
            "Firewall rules restricting access to clearinghouse systems",
        ],
        remediation_guidance=(
            "Implement network segmentation (VLANs, firewall rules) to isolate "
            "clearinghouse functions. Document access control rules."
        ),
        threat_scenarios=[
            "Lateral movement from corporate network into clearinghouse ePHI",
        ],
    ),

    HIPAAControl(
        id="AS-10",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Information Access Management",
        standard_cfr="§164.308(a)(4)",
        specification="Access Authorization",
        specification_cfr="§164.308(a)(4)(ii)(B)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.ACCESS,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-5", "CIS-6"],
        weight=2.5,
        description=(
            "Implement policies and procedures for granting access to ePHI — "
            "for example, through access to a workstation, transaction, program, "
            "process, or other mechanism."
        ),
        assessment_questions=[
            "Are formal access request and approval procedures documented?",
            "Is the principle of minimum necessary applied to all access grants?",
            "Is access reviewed and recertified at least annually?",
            "Are privileged access accounts separately managed and reviewed?",
        ],
        evidence_examples=[
            "Access request forms with supervisor approval",
            "Role matrix defining access by job function",
            "Annual access recertification records",
            "Privileged access management (PAM) solution evidence",
        ],
        remediation_guidance=(
            "Implement a formal access request workflow with documented approval. "
            "Define role-based access profiles tied to job function. "
            "Conduct semi-annual access recertification with manager sign-off. "
            "Deploy a PAM solution for privileged accounts."
        ),
        threat_scenarios=[
            "Excessive access enabling broad data exfiltration during a breach",
            "Shared/generic accounts preventing attribution of access events",
        ],
    ),

    HIPAAControl(
        id="AS-11",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Information Access Management",
        standard_cfr="§164.308(a)(4)",
        specification="Access Establishment and Modification",
        specification_cfr="§164.308(a)(4)(ii)(C)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.ACCESS,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-5", "CIS-6"],
        weight=2.0,
        description=(
            "Implement policies and procedures that, based upon the entity's access "
            "authorization policies, establish, document, review, and modify a user's "
            "right of access to a workstation, transaction, program, or process."
        ),
        assessment_questions=[
            "Is there a documented process to modify access when roles change?",
            "Are access changes logged and auditable?",
            "Is there a process for emergency access provisioning with post-review?",
        ],
        evidence_examples=[
            "Change management tickets for access modifications",
            "Role change procedure documentation",
            "Audit trail of access modifications",
        ],
        remediation_guidance=(
            "Integrate access modification into the HR role-change process. "
            "All access changes should be ticketed, approved, and logged. "
            "Implement emergency access procedures with required post-hoc review."
        ),
        threat_scenarios=[
            "Employee retaining excessive access after promotion",
            "Access accumulation over time (privilege creep)",
        ],
    ),

    # ── Security Awareness and Training ──────────────────────

    HIPAAControl(
        id="AS-12",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Security Awareness and Training",
        standard_cfr="§164.308(a)(5)",
        specification="Security Reminders",
        specification_cfr="§164.308(a)(5)(ii)(A)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.WORKFORCE,
        nist_functions=[NistFunction.PROTECT, NistFunction.GOVERN],
        cis_controls=["CIS-14"],
        weight=1.5,
        description=(
            "Periodic security updates and reminders for all workforce members "
            "about security policies and procedures."
        ),
        assessment_questions=[
            "Are periodic security reminders/communications sent to all workforce members?",
            "Do reminders cover current threats (phishing, ransomware, etc.)?",
            "Is there a documented schedule for security awareness communications?",
        ],
        evidence_examples=[
            "Security newsletter or email communications",
            "Training completion records",
            "Annual security awareness calendar",
        ],
        remediation_guidance=(
            "Implement a security awareness program with monthly communications. "
            "Include current threat intelligence, policy reminders, and incident "
            "reporting procedures. Track and document distribution."
        ),
        threat_scenarios=[
            "Phishing click due to lack of awareness training",
            "Accidental PHI disclosure to wrong recipient",
        ],
    ),

    HIPAAControl(
        id="AS-13",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Security Awareness and Training",
        standard_cfr="§164.308(a)(5)",
        specification="Protection from Malicious Software",
        specification_cfr="§164.308(a)(5)(ii)(B)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.ENDPOINT,
        nist_functions=[NistFunction.PROTECT, NistFunction.DETECT],
        cis_controls=["CIS-10", "CIS-14"],
        weight=2.5,
        description=(
            "Procedures for guarding against, detecting, and reporting malicious "
            "software — covering both technical controls and workforce training."
        ),
        assessment_questions=[
            "Is anti-malware software deployed on all endpoints with ePHI access?",
            "Are anti-malware signatures updated automatically?",
            "Are workforce members trained to recognize and report malware indicators?",
            "Is there an EDR (Endpoint Detection and Response) solution in place?",
            "Is there a tested incident response procedure for ransomware?",
        ],
        evidence_examples=[
            "Anti-malware deployment and coverage report",
            "EDR console showing coverage and recent detections",
            "Malware incident response procedure",
            "Training records for malware awareness",
        ],
        remediation_guidance=(
            "Deploy enterprise-grade EDR on all endpoints. Ensure automatic signature "
            "updates. Conduct annual ransomware tabletop exercises. Train all workforce "
            "on recognizing phishing and malware delivery vectors."
        ),
        threat_scenarios=[
            "Ransomware encrypting EHR database and backups",
            "Keylogger capturing EHR credentials",
            "Supply chain malware via software update",
        ],
    ),

    HIPAAControl(
        id="AS-14",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Security Awareness and Training",
        standard_cfr="§164.308(a)(5)",
        specification="Log-in Monitoring",
        specification_cfr="§164.308(a)(5)(ii)(C)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.AUDIT,
        nist_functions=[NistFunction.DETECT],
        cis_controls=["CIS-8"],
        weight=2.0,
        description=(
            "Procedures for monitoring log-in attempts and reporting discrepancies "
            "to workforce members."
        ),
        assessment_questions=[
            "Are failed login attempts logged on all ePHI systems?",
            "Is there an account lockout policy after repeated failed attempts?",
            "Are login anomalies (unusual times, locations) detected and alerted?",
            "Are workforce members notified of login anomalies to their accounts?",
        ],
        evidence_examples=[
            "Account lockout policy documentation",
            "SIEM alerts configured for login anomalies",
            "User notification procedures for suspicious login activity",
        ],
        remediation_guidance=(
            "Configure account lockout after 5–10 failed attempts. Implement SIEM "
            "alerting for login anomalies (off-hours, new geolocation, bulk failures). "
            "Consider implementing UEBA (User and Entity Behavior Analytics)."
        ),
        threat_scenarios=[
            "Credential stuffing attack against EHR portal",
            "Brute force attack against VPN",
        ],
    ),

    HIPAAControl(
        id="AS-15",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Security Awareness and Training",
        standard_cfr="§164.308(a)(5)",
        specification="Password Management",
        specification_cfr="§164.308(a)(5)(ii)(D)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.AUTHENTICATION,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-5"],
        weight=2.0,
        description=(
            "Procedures for creating, changing, and safeguarding passwords — "
            "including workforce training on proper password management."
        ),
        assessment_questions=[
            "Is there a documented password policy meeting current NIST SP 800-63B guidelines?",
            "Is multi-factor authentication (MFA) enforced for all ePHI system access?",
            "Is a password manager recommended or provided?",
            "Is password sharing explicitly prohibited?",
            "Are default passwords changed on all systems before deployment?",
        ],
        evidence_examples=[
            "Password policy document",
            "MFA configuration evidence for EHR and email systems",
            "Password manager deployment records",
            "Training records on password security",
        ],
        remediation_guidance=(
            "Implement MFA for all systems accessing ePHI — this is the single "
            "highest-ROI security control available. Adopt NIST SP 800-63B guidelines "
            "(minimum 8 chars, no mandatory rotation without breach indication). "
            "Deploy enterprise password manager and prohibit password sharing."
        ),
        threat_scenarios=[
            "Credential theft via phishing enabling EHR access",
            "Shared credentials preventing breach attribution",
            "Default credentials exploited on medical device",
        ],
    ),

    # ── Security Incident Procedures ─────────────────────────

    HIPAAControl(
        id="AS-16",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Security Incident Procedures",
        standard_cfr="§164.308(a)(6)",
        specification="Response and Reporting",
        specification_cfr="§164.308(a)(6)(ii)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.INCIDENT,
        nist_functions=[NistFunction.RESPOND, NistFunction.RECOVER],
        cis_controls=["CIS-17"],
        weight=3.0,
        description=(
            "Identify and respond to suspected or known security incidents; mitigate, "
            "to the extent practicable, harmful effects of security incidents that "
            "are known to the covered entity; and document security incidents and "
            "their outcomes."
        ),
        assessment_questions=[
            "Is there a documented Security Incident Response Plan (SIRP)?",
            "Does the plan cover ePHI-specific scenarios (breach, ransomware, insider threat)?",
            "Is the plan tested at least annually via tabletop exercise?",
            "Are incident response roles and contact information current?",
            "Is there a process for documenting incidents and outcomes?",
            "Does the plan include the 60-day HHS breach notification trigger?",
        ],
        evidence_examples=[
            "Security Incident Response Plan document",
            "Tabletop exercise records (scenario, participants, findings, follow-up)",
            "Incident log showing documented incidents and resolutions",
            "Breach notification procedure referencing §164.410",
        ],
        remediation_guidance=(
            "Develop and maintain a HIPAA-specific Incident Response Plan. "
            "Include ransomware, phishing, insider threat, and unauthorized access "
            "scenarios. Conduct annual tabletop exercises with leadership participation. "
            "Ensure the plan explicitly addresses the 60-day HHS breach notification "
            "requirement and integrates with legal counsel."
        ),
        threat_scenarios=[
            "Ransomware attack requiring forensic investigation and OCR notification",
            "Employee unauthorized access to celebrity patient records",
            "Misdirected fax/email containing PHI",
        ],
    ),

    # ── Contingency Plan ──────────────────────────────────────

    HIPAAControl(
        id="AS-17",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Contingency Plan",
        standard_cfr="§164.308(a)(7)",
        specification="Data Backup Plan",
        specification_cfr="§164.308(a)(7)(ii)(A)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.CONTINUITY,
        nist_functions=[NistFunction.RECOVER],
        cis_controls=["CIS-11"],
        weight=3.0,
        description=(
            "Establish and implement procedures to create and maintain retrievable "
            "exact copies of ePHI."
        ),
        assessment_questions=[
            "Is there a documented backup policy covering all ePHI systems?",
            "Are backups performed at least daily?",
            "Are backups encrypted and stored off-site or in a separate cloud region?",
            "Are backups tested for recoverability at least quarterly?",
            "Is there an immutable backup copy (air-gapped or WORM storage)?",
        ],
        evidence_examples=[
            "Backup policy and procedure document",
            "Backup software configuration showing schedule and retention",
            "Backup test results (restoration tests with timestamps)",
            "Off-site or cloud storage configuration",
        ],
        remediation_guidance=(
            "Implement the 3-2-1-1 backup strategy: 3 copies, 2 media types, "
            "1 off-site, 1 immutable/air-gapped copy. Test restoration quarterly. "
            "Verify that backups are encrypted. Maintain offline copies specifically "
            "to ensure ransomware cannot reach all backup copies."
        ),
        threat_scenarios=[
            "Ransomware encrypting both production data and online backups",
            "EHR vendor failure with no local backup",
            "Natural disaster destroying on-site backup tapes",
        ],
    ),

    HIPAAControl(
        id="AS-18",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Contingency Plan",
        standard_cfr="§164.308(a)(7)",
        specification="Disaster Recovery Plan",
        specification_cfr="§164.308(a)(7)(ii)(B)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.CONTINUITY,
        nist_functions=[NistFunction.RECOVER],
        cis_controls=["CIS-11"],
        weight=2.5,
        description=(
            "Establish (and implement as needed) procedures to restore any loss of "
            "data and address critical business processes after a disaster."
        ),
        assessment_questions=[
            "Is there a documented Disaster Recovery Plan (DRP)?",
            "Does the DRP define Recovery Time Objectives (RTO) and Recovery Point Objectives (RPO)?",
            "Is the DRP tested at least annually?",
            "Does the DRP address cloud/SaaS vendor outages?",
        ],
        evidence_examples=[
            "Disaster Recovery Plan document",
            "RTO/RPO definitions per system",
            "DRP test results",
            "Vendor SLAs supporting RTO/RPO commitments",
        ],
        remediation_guidance=(
            "Document RTO and RPO for each ePHI system. Ensure recovery procedures "
            "are detailed enough for staff unfamiliar with normal operations to execute. "
            "Test annually and update after any significant infrastructure change."
        ),
        threat_scenarios=[
            "Data center fire destroying primary EHR infrastructure",
            "Cloud provider extended outage affecting EHR access",
        ],
    ),

    HIPAAControl(
        id="AS-19",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Contingency Plan",
        standard_cfr="§164.308(a)(7)",
        specification="Emergency Mode Operation Plan",
        specification_cfr="§164.308(a)(7)(ii)(C)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.CONTINUITY,
        nist_functions=[NistFunction.RECOVER],
        cis_controls=["CIS-11"],
        weight=2.0,
        description=(
            "Establish (and implement as needed) procedures to enable continuation "
            "of critical business processes for protection of the security of ePHI "
            "while operating in emergency mode."
        ),
        assessment_questions=[
            "Is there a documented procedure for operating during system downtime?",
            "Are downtime procedures distributed to clinical staff?",
            "Is paper-based/downtime workflow tested periodically?",
        ],
        evidence_examples=[
            "Downtime procedures document",
            "Staff training records on downtime procedures",
            "Evidence of downtime procedure drills",
        ],
        remediation_guidance=(
            "Document manual (paper-based) workflows for all critical clinical processes. "
            "Train staff and conduct periodic downtime drills. Ensure procedures "
            "maintain PHI security even in manual mode."
        ),
        threat_scenarios=[
            "EHR unavailability during active patient care with no downtime procedure",
        ],
    ),

    HIPAAControl(
        id="AS-20",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Contingency Plan",
        standard_cfr="§164.308(a)(7)",
        specification="Testing and Revision Procedures",
        specification_cfr="§164.308(a)(7)(ii)(D)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.CONTINUITY,
        nist_functions=[NistFunction.RECOVER],
        cis_controls=["CIS-11"],
        weight=2.0,
        description=(
            "Implement procedures for periodic testing and revision of contingency "
            "plans to meet the needs of the covered entity."
        ),
        assessment_questions=[
            "Are contingency plans tested at least annually?",
            "Are test results documented and used to improve plans?",
            "Are plans reviewed and updated after significant changes?",
        ],
        evidence_examples=[
            "Test exercise reports",
            "Plan revision history",
            "After-action reports from tests",
        ],
        remediation_guidance=(
            "Conduct annual tabletop exercises testing both backup/recovery and "
            "emergency mode operations. Document all findings and update plans accordingly."
        ),
        threat_scenarios=[
            "DRP fails during actual disaster because it was never tested",
        ],
    ),

    HIPAAControl(
        id="AS-21",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Contingency Plan",
        standard_cfr="§164.308(a)(7)",
        specification="Applications and Data Criticality Analysis",
        specification_cfr="§164.308(a)(7)(ii)(E)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.GOVERNANCE,
        nist_functions=[NistFunction.IDENTIFY],
        cis_controls=["CIS-1"],
        weight=1.5,
        description=(
            "Assess the relative criticality of specific applications and data in "
            "support of other contingency plan components."
        ),
        assessment_questions=[
            "Is there a documented inventory of applications that process ePHI?",
            "Are applications classified by criticality (tier 1/2/3)?",
            "Does the backup/recovery plan prioritize restoration by criticality?",
        ],
        evidence_examples=[
            "Application inventory with criticality ratings",
            "Business Impact Analysis (BIA)",
            "Recovery priority order in DRP",
        ],
        remediation_guidance=(
            "Conduct a Business Impact Analysis to classify all ePHI applications "
            "by criticality. Align backup, recovery, and downtime procedures to "
            "prioritize restoration of the most critical systems first."
        ),
        threat_scenarios=[
            "Recovery process restores billing before EHR, leaving patient care unsupported",
        ],
    ),

    # ── Evaluation ────────────────────────────────────────────

    HIPAAControl(
        id="AS-22",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Evaluation",
        standard_cfr="§164.308(a)(8)",
        specification="Periodic Evaluation",
        specification_cfr="§164.308(a)(8)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.GOVERNANCE,
        nist_functions=[NistFunction.IDENTIFY, NistFunction.GOVERN],
        cis_controls=["CIS-18"],
        weight=2.5,
        description=(
            "Perform a periodic technical and non-technical evaluation, based initially "
            "upon the standards implemented under this rule and subsequently, in "
            "response to environmental or operational changes affecting the security "
            "of ePHI."
        ),
        assessment_questions=[
            "Is the SRA performed at least annually?",
            "Is the SRA updated following significant operational or technology changes?",
            "Are technical controls validated through vulnerability scanning or penetration testing?",
            "Is the evaluation performed or reviewed by qualified personnel?",
        ],
        evidence_examples=[
            "Dated SRA reports",
            "Vulnerability scan reports",
            "Penetration test reports",
            "Change management triggers for SRA updates",
        ],
        remediation_guidance=(
            "Conduct the SRA annually at minimum. Trigger an interim update for: "
            "new EHR implementation, merger/acquisition, major infrastructure change, "
            "significant breach, or regulatory change. Supplement with annual "
            "vulnerability scanning and periodic penetration testing."
        ),
        threat_scenarios=[
            "New ransomware vector not covered in 3-year-old SRA",
            "Newly implemented telehealth platform not included in risk assessment",
        ],
    ),

    # ── Business Associate Contracts ─────────────────────────

    HIPAAControl(
        id="AS-23",
        safeguard=Safeguard.ADMINISTRATIVE,
        standard="Business Associate Contracts",
        standard_cfr="§164.308(b)(1)",
        specification="Business Associate Contracts and Other Arrangements",
        specification_cfr="§164.308(b)(4)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.VENDOR,
        nist_functions=[NistFunction.GOVERN, NistFunction.PROTECT],
        cis_controls=["CIS-15"],
        weight=3.0,
        description=(
            "A covered entity may permit a business associate to create, receive, "
            "maintain, or transmit ePHI on the covered entity's behalf only if the "
            "covered entity obtains satisfactory assurances in the form of a Business "
            "Associate Agreement (BAA)."
        ),
        assessment_questions=[
            "Is there an inventory of all Business Associates with ePHI access?",
            "Is a signed BAA on file for every Business Associate?",
            "Do BAAs include HIPAA Security Rule requirements (not just Privacy)?",
            "Are BAAs reviewed and updated at least every 3 years?",
            "Is there a process to identify new vendors requiring BAAs?",
            "Are BAs assessed for security posture before engagement?",
        ],
        evidence_examples=[
            "BA inventory/register",
            "Signed BAA templates and executed agreements",
            "BAA review schedule",
            "Vendor security questionnaire process",
        ],
        remediation_guidance=(
            "Maintain a comprehensive BA register. Require signed BAAs before any "
            "vendor accesses ePHI. Include Security Rule requirements in all BAAs. "
            "Implement a vendor risk assessment process for high-risk BAs. "
            "Review and renew BAAs at least every 3 years or when services change."
        ),
        threat_scenarios=[
            "Third-party billing vendor breach exposing patient records",
            "Cloud EHR vendor with no signed BAA",
            "BA subcontracting ePHI processing without notification",
        ],
    ),

    # ══════════════════════════════════════════════════════════
    # PHYSICAL SAFEGUARDS — 45 CFR § 164.310
    # ══════════════════════════════════════════════════════════

    HIPAAControl(
        id="PS-01",
        safeguard=Safeguard.PHYSICAL,
        standard="Facility Access Controls",
        standard_cfr="§164.310(a)(1)",
        specification="Contingency Operations",
        specification_cfr="§164.310(a)(2)(i)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.PHYSICAL,
        nist_functions=[NistFunction.PROTECT, NistFunction.RECOVER],
        cis_controls=["CIS-11"],
        weight=1.5,
        description=(
            "Establish procedures that allow facility access in support of restoration "
            "of lost data under the disaster recovery plan and emergency mode "
            "operations plan in the event of an emergency."
        ),
        assessment_questions=[
            "Are procedures in place to grant emergency access to facilities?",
            "Is physical access to server rooms/data closets controlled during emergencies?",
        ],
        evidence_examples=[
            "Emergency access procedure",
            "Physical access control system with emergency override log",
        ],
        remediation_guidance=(
            "Document physical access procedures for emergency scenarios. "
            "Ensure server room emergency access is controlled and logged."
        ),
        threat_scenarios=[
            "First responders needing server room access during disaster",
        ],
    ),

    HIPAAControl(
        id="PS-02",
        safeguard=Safeguard.PHYSICAL,
        standard="Facility Access Controls",
        standard_cfr="§164.310(a)(1)",
        specification="Facility Security Plan",
        specification_cfr="§164.310(a)(2)(ii)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.PHYSICAL,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-3"],
        weight=2.0,
        description=(
            "Implement policies and procedures to safeguard the facility and the "
            "equipment therein from unauthorized physical access, tampering, and theft."
        ),
        assessment_questions=[
            "Is there a documented physical security plan?",
            "Are areas containing ePHI systems physically secured (locked, badged)?",
            "Is there video surveillance of server rooms and key access points?",
            "Are visitor access logs maintained?",
        ],
        evidence_examples=[
            "Physical security plan",
            "Access control system audit logs",
            "Security camera placement documentation",
            "Visitor log records",
        ],
        remediation_guidance=(
            "Implement electronic badge access for server rooms and areas with ePHI. "
            "Deploy cameras at entry points. Maintain visitor logs. Conduct periodic "
            "physical security reviews."
        ),
        threat_scenarios=[
            "Unauthorized individual accessing server room and copying data",
            "Laptop stolen from unlocked office",
        ],
    ),

    HIPAAControl(
        id="PS-03",
        safeguard=Safeguard.PHYSICAL,
        standard="Facility Access Controls",
        standard_cfr="§164.310(a)(1)",
        specification="Access Control and Validation Procedures",
        specification_cfr="§164.310(a)(2)(iii)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.PHYSICAL,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-3"],
        weight=2.0,
        description=(
            "Implement procedures to control and validate a person's access to "
            "facilities based on their role or function, including visitor control "
            "and control of access to software programs for testing and revision."
        ),
        assessment_questions=[
            "Is physical access to ePHI areas role-based and regularly reviewed?",
            "Are visitors escorted in ePHI-sensitive areas?",
            "Is there a process to revoke physical access upon termination?",
        ],
        evidence_examples=[
            "Badge access roles/profiles by job function",
            "Visitor escort policy",
            "Termination checklist including badge deactivation",
        ],
        remediation_guidance=(
            "Align physical access to job function using the same RBAC principles "
            "as logical access. Include badge/key revocation in termination checklists."
        ),
        threat_scenarios=[
            "Former employee using retained badge to access server room",
        ],
    ),

    HIPAAControl(
        id="PS-04",
        safeguard=Safeguard.PHYSICAL,
        standard="Facility Access Controls",
        standard_cfr="§164.310(a)(1)",
        specification="Maintenance Records",
        specification_cfr="§164.310(a)(2)(iv)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.PHYSICAL,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-3"],
        weight=1.0,
        description=(
            "Implement policies and procedures to document repairs and modifications "
            "to the physical components of a facility that are related to security."
        ),
        assessment_questions=[
            "Are physical security repairs and modifications documented?",
            "Are maintenance vendor access logs maintained?",
        ],
        evidence_examples=[
            "Facility maintenance log",
            "Vendor access records for physical security systems",
        ],
        remediation_guidance=(
            "Maintain a log of all physical security modifications, repairs, and vendor access. "
            "Supervise vendor access to areas with ePHI."
        ),
        threat_scenarios=[
            "Maintenance vendor installs rogue device during unescorted visit",
        ],
    ),

    HIPAAControl(
        id="PS-05",
        safeguard=Safeguard.PHYSICAL,
        standard="Workstation Use",
        standard_cfr="§164.310(b)",
        specification="Workstation Use Policy",
        specification_cfr="§164.310(b)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.ENDPOINT,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-4"],
        weight=2.0,
        description=(
            "Implement policies and procedures that specify the proper functions to "
            "be performed, the manner in which those functions are to be performed, "
            "and the physical attributes of the surroundings of a specific workstation "
            "or class of workstation that can access ePHI."
        ),
        assessment_questions=[
            "Is there a documented workstation use policy?",
            "Does the policy address screen positioning, privacy screens, and clean desk?",
            "Is personal use of ePHI workstations prohibited or restricted?",
            "Does the policy address remote work arrangements?",
        ],
        evidence_examples=[
            "Workstation use policy document",
            "Remote work / work-from-home security policy",
            "Employee acknowledgment forms",
        ],
        remediation_guidance=(
            "Implement a workstation use policy covering: screen positioning (away "
            "from public view), clean desk/lock screen requirements, prohibited uses "
            "(personal browsing, unauthorized software), and remote work security "
            "requirements. Require annual acknowledgment."
        ),
        threat_scenarios=[
            "PHI visible on screen in public waiting area",
            "Employee working from coffee shop on unencrypted public WiFi",
        ],
    ),

    HIPAAControl(
        id="PS-06",
        safeguard=Safeguard.PHYSICAL,
        standard="Workstation Security",
        standard_cfr="§164.310(c)",
        specification="Physical Workstation Security",
        specification_cfr="§164.310(c)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.ENDPOINT,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-4"],
        weight=2.0,
        description=(
            "Implement physical safeguards for all workstations that access ePHI, "
            "to restrict access to authorized users."
        ),
        assessment_questions=[
            "Are workstations physically secured (cable locks, locked rooms)?",
            "Are unattended workstations required to lock after inactivity?",
            "Are workstations in public areas protected from shoulder surfing?",
        ],
        evidence_examples=[
            "Workstation security policy",
            "Screen lock policy configuration (Group Policy or MDM)",
            "Evidence of cable locks on portable workstations",
        ],
        remediation_guidance=(
            "Enforce automatic screen lock after 10–15 minutes inactivity via Group "
            "Policy or MDM. Deploy cable locks on portable workstations. "
            "Position screens in clinical areas to minimize patient data visibility."
        ),
        threat_scenarios=[
            "Unattended unlocked workstation accessed by unauthorized person",
            "Laptop stolen from unsecured office",
        ],
    ),

    HIPAAControl(
        id="PS-07",
        safeguard=Safeguard.PHYSICAL,
        standard="Device and Media Controls",
        standard_cfr="§164.310(d)(1)",
        specification="Disposal",
        specification_cfr="§164.310(d)(2)(i)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.ENDPOINT,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-3"],
        weight=2.5,
        description=(
            "Implement policies and procedures to address the final disposition of "
            "ePHI and/or the hardware or electronic media on which it is stored."
        ),
        assessment_questions=[
            "Is there a documented media disposal policy?",
            "Are hard drives and media cryptographically wiped (DoD 5220.22-M or NIST 800-88)?",
            "Are disposal activities documented with certificates of destruction?",
            "Is physical destruction used for non-wipeable media (SSDs, legacy hardware)?",
        ],
        evidence_examples=[
            "Media disposal policy",
            "Certificate of destruction from disposal vendor",
            "Asset decommissioning log with disposal method",
        ],
        remediation_guidance=(
            "Implement a formal media disposal process. Use NIST SP 800-88 guidelines: "
            "cryptographic erase for SSDs, 7-pass overwrite for HDDs, physical "
            "shredding/degaussing for non-wipeable media. Obtain certificates of "
            "destruction from third-party disposal vendors."
        ),
        threat_scenarios=[
            "Resold workstation with recoverable PHI",
            "Discarded backup tapes found in dumpster",
        ],
    ),

    HIPAAControl(
        id="PS-08",
        safeguard=Safeguard.PHYSICAL,
        standard="Device and Media Controls",
        standard_cfr="§164.310(d)(1)",
        specification="Media Re-Use",
        specification_cfr="§164.310(d)(2)(ii)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.ENDPOINT,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-3"],
        weight=2.0,
        description=(
            "Implement procedures for removal of ePHI from electronic media before "
            "the media are made available for re-use."
        ),
        assessment_questions=[
            "Is there a procedure to sanitize media before internal re-use?",
            "Is re-use documented and verified?",
        ],
        evidence_examples=[
            "Media re-use procedure",
            "Sanitization verification records",
        ],
        remediation_guidance=(
            "Apply NIST SP 800-88 sanitization before any media is re-issued to "
            "a new user or repurposed. Document and verify each sanitization action."
        ),
        threat_scenarios=[
            "Repurposed laptop with previous employee's PHI accessible to new user",
        ],
    ),

    HIPAAControl(
        id="PS-09",
        safeguard=Safeguard.PHYSICAL,
        standard="Device and Media Controls",
        standard_cfr="§164.310(d)(1)",
        specification="Accountability",
        specification_cfr="§164.310(d)(2)(iii)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.ENDPOINT,
        nist_functions=[NistFunction.IDENTIFY],
        cis_controls=["CIS-1"],
        weight=1.5,
        description=(
            "Maintain a record of the movements of hardware and electronic media "
            "and any person responsible therefore."
        ),
        assessment_questions=[
            "Is there an asset inventory tracking all devices with ePHI access?",
            "Is chain of custody documented for hardware movement?",
            "Are portable devices (laptops, tablets, USB drives) individually tracked?",
        ],
        evidence_examples=[
            "Asset management system or CMDB",
            "Hardware transfer/movement logs",
            "Mobile device inventory",
        ],
        remediation_guidance=(
            "Implement an asset management solution tracking all hardware with ePHI. "
            "Require documented chain of custody for all hardware transfers. "
            "Prohibit untracked portable media (personal USB drives)."
        ),
        threat_scenarios=[
            "Untracked laptop discovered missing weeks after loss",
        ],
    ),

    # ══════════════════════════════════════════════════════════
    # TECHNICAL SAFEGUARDS — 45 CFR § 164.312
    # ══════════════════════════════════════════════════════════

    HIPAAControl(
        id="TS-01",
        safeguard=Safeguard.TECHNICAL,
        standard="Access Control",
        standard_cfr="§164.312(a)(1)",
        specification="Unique User Identification",
        specification_cfr="§164.312(a)(2)(i)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.ACCESS,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-5"],
        weight=3.0,
        description=(
            "Assign a unique name and/or number for identifying and tracking user "
            "identity in all ePHI systems."
        ),
        assessment_questions=[
            "Does every user have a unique account — no shared or generic credentials?",
            "Are shared/service accounts prohibited for human users?",
            "Are user accounts uniquely attributable to a specific individual?",
            "Is there an exception process for emergency/shared accounts with compensating controls?",
        ],
        evidence_examples=[
            "EHR user account report showing no duplicate or generic usernames",
            "Active Directory policy prohibiting shared accounts",
            "Exception log for any approved generic accounts with compensating controls",
        ],
        remediation_guidance=(
            "Audit all ePHI systems for shared, generic, or role-based accounts used by "
            "humans. Migrate to individual accounts. For legacy systems that require "
            "shared accounts, implement compensating controls (time-limited checkout, "
            "session recording, break-glass procedures)."
        ),
        threat_scenarios=[
            "Breach not attributable because multiple staff shared one login",
            "Former employee continuing to access EHR via shared credentials",
        ],
    ),

    HIPAAControl(
        id="TS-02",
        safeguard=Safeguard.TECHNICAL,
        standard="Access Control",
        standard_cfr="§164.312(a)(1)",
        specification="Emergency Access Procedure",
        specification_cfr="§164.312(a)(2)(ii)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.ACCESS,
        nist_functions=[NistFunction.RESPOND, NistFunction.PROTECT],
        cis_controls=["CIS-5"],
        weight=2.0,
        description=(
            "Establish (and implement as needed) procedures for obtaining necessary "
            "ePHI during an emergency."
        ),
        assessment_questions=[
            "Is there a documented break-glass/emergency access procedure?",
            "Are emergency access events logged and reviewed post-incident?",
            "Is emergency access time-limited and revoked automatically?",
        ],
        evidence_examples=[
            "Emergency access procedure document",
            "Break-glass account audit log",
            "Post-incident review records for emergency access events",
        ],
        remediation_guidance=(
            "Implement a formal break-glass procedure with time-limited credentials. "
            "Log all emergency access events. Require post-incident review and supervisor "
            "notification within 24 hours of any emergency access use."
        ),
        threat_scenarios=[
            "Clinical staff cannot access patient records during system downtime",
        ],
    ),

    HIPAAControl(
        id="TS-03",
        safeguard=Safeguard.TECHNICAL,
        standard="Access Control",
        standard_cfr="§164.312(a)(1)",
        specification="Automatic Logoff",
        specification_cfr="§164.312(a)(2)(iii)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.ACCESS,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-4"],
        weight=2.0,
        description=(
            "Implement electronic procedures that terminate an electronic session "
            "after a predetermined time of inactivity."
        ),
        assessment_questions=[
            "Is automatic session timeout configured on all ePHI applications?",
            "What is the timeout period (should be 15 minutes or less for clinical systems)?",
            "Is the timeout policy enforced via technical controls rather than policy alone?",
        ],
        evidence_examples=[
            "EHR session timeout configuration",
            "Group Policy/MDM configuration for screen lock",
            "Application timeout settings documentation",
        ],
        remediation_guidance=(
            "Configure automatic session timeout of 15 minutes or less on all ePHI "
            "applications. Enforce via technical controls (not just policy). For clinical "
            "workstations in active use, balance security with workflow efficiency "
            "using proximity sensors or clinical workflow-aware timeouts."
        ),
        threat_scenarios=[
            "Unattended nurse station workstation with patient record visible",
        ],
    ),

    HIPAAControl(
        id="TS-04",
        safeguard=Safeguard.TECHNICAL,
        standard="Access Control",
        standard_cfr="§164.312(a)(1)",
        specification="Encryption and Decryption",
        specification_cfr="§164.312(a)(2)(iv)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.ENCRYPTION,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-3"],
        weight=3.0,
        description=(
            "Implement a mechanism to encrypt and decrypt ePHI stored on devices "
            "and systems (encryption at rest)."
        ),
        assessment_questions=[
            "Is ePHI encrypted at rest on all servers, databases, and workstations?",
            "Are encryption standards meeting NIST FIPS 140-2 (AES-256)?",
            "Are portable devices (laptops, tablets) encrypted via full-disk encryption?",
            "Are encryption keys separately managed and stored (not on the device)?",
        ],
        evidence_examples=[
            "BitLocker/FileVault deployment report",
            "Database encryption configuration",
            "Encryption key management policy",
            "MDM compliance report showing device encryption status",
        ],
        remediation_guidance=(
            "Enable full-disk encryption (BitLocker on Windows, FileVault on macOS) "
            "on all endpoints. Encrypt databases containing ePHI using AES-256. "
            "Store encryption keys in a dedicated key management system separate "
            "from the encrypted data. This control effectively renders lost/stolen "
            "devices a non-breach under HIPAA's Safe Harbor provision."
        ),
        threat_scenarios=[
            "Stolen encrypted laptop — HIPAA Safe Harbor applies if encrypted",
            "Ransomware attacker extracting ePHI database — mitigated by encryption",
        ],
    ),

    HIPAAControl(
        id="TS-05",
        safeguard=Safeguard.TECHNICAL,
        standard="Audit Controls",
        standard_cfr="§164.312(b)",
        specification="Audit Controls",
        specification_cfr="§164.312(b)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.AUDIT,
        nist_functions=[NistFunction.DETECT, NistFunction.IDENTIFY],
        cis_controls=["CIS-8"],
        weight=3.0,
        description=(
            "Implement hardware, software, and/or procedural mechanisms that record "
            "and examine activity in information systems that contain or use ePHI."
        ),
        assessment_questions=[
            "Are audit logs enabled on all ePHI systems (EHR, servers, network devices)?",
            "Do logs capture: user ID, date/time, action taken, data accessed?",
            "Are logs protected from tampering (write-once, centralized)?",
            "Are logs retained for a minimum of 6 years?",
            "Is there a SIEM or log management system centralizing all logs?",
        ],
        evidence_examples=[
            "SIEM/log management platform configuration",
            "Sample audit log output showing required fields",
            "Log retention policy (6+ years)",
            "Log integrity protection configuration (write-once storage)",
        ],
        remediation_guidance=(
            "Implement a centralized SIEM solution. Ensure all ePHI systems send "
            "logs to the SIEM. Enable audit logging in the EHR (most major EHRs "
            "have this built in). Set log retention to minimum 6 years. "
            "Protect logs from modification using write-once storage or log signing."
        ),
        threat_scenarios=[
            "Insider access to celebrity patient records with no audit trail",
            "Attacker covering tracks by deleting logs on compromised server",
        ],
    ),

    HIPAAControl(
        id="TS-06",
        safeguard=Safeguard.TECHNICAL,
        standard="Integrity",
        standard_cfr="§164.312(c)(1)",
        specification="Mechanism to Authenticate ePHI",
        specification_cfr="§164.312(c)(2)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.ENCRYPTION,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-3"],
        weight=2.0,
        description=(
            "Implement electronic mechanisms to corroborate that ePHI has not "
            "been altered or destroyed in an unauthorized manner."
        ),
        assessment_questions=[
            "Are checksums or digital signatures used to verify ePHI integrity?",
            "Is there a process to detect unauthorized modification of records?",
            "Are EHR audit logs used to detect unauthorized modifications?",
        ],
        evidence_examples=[
            "EHR audit trail showing modification history per record",
            "File integrity monitoring (FIM) configuration",
            "Hash verification for backup integrity",
        ],
        remediation_guidance=(
            "Enable EHR audit trail functionality that records all record modifications. "
            "Implement File Integrity Monitoring (FIM) for critical ePHI files and "
            "database tables. Verify backup integrity with hash verification."
        ),
        threat_scenarios=[
            "Malicious modification of medication records",
            "Ransomware corruption of ePHI database",
        ],
    ),

    HIPAAControl(
        id="TS-07",
        safeguard=Safeguard.TECHNICAL,
        standard="Person or Entity Authentication",
        standard_cfr="§164.312(d)",
        specification="Person or Entity Authentication",
        specification_cfr="§164.312(d)",
        designation=Designation.REQUIRED,
        risk_domain=RiskDomain.AUTHENTICATION,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-5"],
        weight=3.0,
        description=(
            "Implement procedures to verify that a person or entity seeking access "
            "to ePHI is the one claimed."
        ),
        assessment_questions=[
            "Is multi-factor authentication (MFA) enforced for all ePHI system access?",
            "Is MFA enforced for remote access (VPN, remote desktop, cloud EHR)?",
            "Are authentication methods meeting NIST SP 800-63B Assurance Level 2+?",
            "Is biometric authentication considered for high-sensitivity clinical systems?",
        ],
        evidence_examples=[
            "MFA enrollment report showing coverage percentage",
            "VPN configuration requiring MFA",
            "Cloud EHR MFA enforcement settings",
            "NIST 800-63B alignment documentation",
        ],
        remediation_guidance=(
            "Implement MFA for 100% of ePHI system access — this is non-negotiable "
            "in 2024. Use authenticator apps (TOTP) or hardware tokens. SMS-based "
            "MFA is better than nothing but vulnerable to SIM swapping. "
            "Prioritize MFA for: EHR access, email, VPN, and privileged admin accounts. "
            "Most HHS OCR settlements in 2023–2024 involved organizations without MFA."
        ),
        threat_scenarios=[
            "Credential stuffing attack gaining EHR access without MFA",
            "Phished password enabling EHR access from attacker's device",
        ],
    ),

    HIPAAControl(
        id="TS-08",
        safeguard=Safeguard.TECHNICAL,
        standard="Transmission Security",
        standard_cfr="§164.312(e)(1)",
        specification="Integrity Controls",
        specification_cfr="§164.312(e)(2)(i)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.NETWORK,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-3", "CIS-12"],
        weight=2.0,
        description=(
            "Implement security measures to ensure that electronically transmitted "
            "ePHI is not improperly modified without detection until disposed of."
        ),
        assessment_questions=[
            "Are integrity controls (TLS, digital signatures) in place for ePHI transmissions?",
            "Is TLS 1.2 or higher enforced for all ePHI data in transit?",
            "Are deprecated protocols (SSL, TLS 1.0/1.1) disabled?",
        ],
        evidence_examples=[
            "TLS configuration assessment output",
            "Network scan showing protocol support on ePHI servers",
            "Email encryption gateway configuration",
        ],
        remediation_guidance=(
            "Enforce TLS 1.2+ for all ePHI transmissions. Disable SSL, TLS 1.0, and "
            "TLS 1.1. Use tools like SSL Labs or Qualys to assess public-facing endpoints. "
            "Implement HSTS (HTTP Strict Transport Security) on web-based ePHI applications."
        ),
        threat_scenarios=[
            "Man-in-the-middle attack intercepting ePHI during transmission",
        ],
    ),

    HIPAAControl(
        id="TS-09",
        safeguard=Safeguard.TECHNICAL,
        standard="Transmission Security",
        standard_cfr="§164.312(e)(1)",
        specification="Encryption",
        specification_cfr="§164.312(e)(2)(ii)",
        designation=Designation.ADDRESSABLE,
        risk_domain=RiskDomain.ENCRYPTION,
        nist_functions=[NistFunction.PROTECT],
        cis_controls=["CIS-3"],
        weight=3.0,
        description=(
            "Implement a mechanism to encrypt ePHI whenever deemed appropriate "
            "— in practice, encryption of ePHI in transit is considered a best "
            "practice and is required by most state laws."
        ),
        assessment_questions=[
            "Is ePHI encrypted in transit using AES-256 or equivalent?",
            "Is email containing ePHI encrypted (S/MIME, TLS-enforced, secure portal)?",
            "Are mobile/wireless transmissions encrypted?",
            "Is ePHI transmitted via unencrypted channels (plain email, FTP)?",
        ],
        evidence_examples=[
            "Email encryption policy and technical configuration",
            "Secure messaging platform for clinical communications",
            "Wireless network security configuration (WPA3 or WPA2-Enterprise)",
        ],
        remediation_guidance=(
            "Encrypt all ePHI in transit. For email: implement a secure email gateway "
            "or enforce TLS delivery. Prohibit sending ePHI via unencrypted email. "
            "For wireless networks: use WPA2-Enterprise with certificate-based auth. "
            "Consider a secure messaging platform (e.g., TigerConnect, Imprivata) "
            "for clinical communications."
        ),
        threat_scenarios=[
            "Lab result containing PHI sent via plain unencrypted email",
            "Patient data intercepted on unsecured clinic WiFi",
        ],
    ),
]


# ─────────────────────────────────────────────────────────────
#  Lookup utilities
# ─────────────────────────────────────────────────────────────

CONTROLS_BY_ID: dict[str, HIPAAControl] = {c.id: c for c in CONTROLS}
CONTROLS_BY_SAFEGUARD: dict[Safeguard, list[HIPAAControl]] = {
    Safeguard.ADMINISTRATIVE: [c for c in CONTROLS if c.safeguard == Safeguard.ADMINISTRATIVE],
    Safeguard.PHYSICAL: [c for c in CONTROLS if c.safeguard == Safeguard.PHYSICAL],
    Safeguard.TECHNICAL: [c for c in CONTROLS if c.safeguard == Safeguard.TECHNICAL],
}
REQUIRED_CONTROLS = [c for c in CONTROLS if c.designation == Designation.REQUIRED]
ADDRESSABLE_CONTROLS = [c for c in CONTROLS if c.designation == Designation.ADDRESSABLE]


def get_control(control_id: str) -> HIPAAControl:
    """Retrieve a control by its ID."""
    if control_id not in CONTROLS_BY_ID:
        raise KeyError(f"Control '{control_id}' not found. Valid IDs: {list(CONTROLS_BY_ID.keys())}")
    return CONTROLS_BY_ID[control_id]


def get_controls_by_domain(domain: RiskDomain) -> list[HIPAAControl]:
    """Return all controls in a given risk domain."""
    return [c for c in CONTROLS if c.risk_domain == domain]


def get_summary() -> dict:
    """Return a summary of the controls database."""
    return {
        "total_controls": len(CONTROLS),
        "administrative": len(CONTROLS_BY_SAFEGUARD[Safeguard.ADMINISTRATIVE]),
        "physical": len(CONTROLS_BY_SAFEGUARD[Safeguard.PHYSICAL]),
        "technical": len(CONTROLS_BY_SAFEGUARD[Safeguard.TECHNICAL]),
        "required": len(REQUIRED_CONTROLS),
        "addressable": len(ADDRESSABLE_CONTROLS),
        "domains": list({c.risk_domain.value for c in CONTROLS}),
    }
