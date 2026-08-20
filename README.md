# Detections.ai Project

A personal **Detection Engineering repository** used to store and organize detection rules created and improved through [detections.ai](https://detections.ai/).

I use the **detections.ai AI Assistant** to help develop detection logic based on threat research, attacker behaviors, and detection ideas. The generated rules are then **manually reviewed, validated, and refined** before being contributed to the detections.ai community and added to this repository.

The repository focuses primarily on:

* Behavioral detection logic
* Microsoft Defender XDR
* KQL / Advanced Hunting
* Suricata and YARA rules
* MITRE ATT&CK aligned detections
* SOC and threat-hunting use cases

---

## Workflow

```text
Detection Idea / Threat Research
        ↓
detections.ai AI Assistant
        ↓
Detection Rule
        ↓
Manual Review & Tuning
        ↓
Community Contribution
        ↓
GitHub Repository
```

---

## Purpose

This repository is used for:

* Storing detections created or improved with detections.ai
* Organizing detection rules by language and platform
* Maintaining public detection engineering work
* Building a personal portfolio of practical detection logic
* Improving detections through review, tuning, and validation
* Contributing detection content to the security community

---

## Repository Structure

```text
Detections.ai-Project/
├── Detections.ai/
│   ├── KQL/
│   ├── Suricata/
│   └── YARA/
└── README.md
```

The structure may evolve as new detection languages, platforms, and use cases are added.

---

## AI-Assisted, Analyst-Reviewed

AI is used to accelerate detection development, but generated rules are **not accepted blindly**.

Each detection is reviewed with consideration for:

* Detection logic
* Syntax
* Telemetry assumptions
* Potential false positives
* MITRE ATT&CK mapping
* Practical investigation value

---

## Disclaimer

Detections in this repository are intended for **defensive security, research, and educational purposes**.

Rules should be tested and tuned according to the telemetry, environment, and baseline activity of the target organization before production deployment.

---

**AI Assisted. Analyst Reviewed. Community Contributed.**
