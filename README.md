# TLS Behavioral Intelligence Engine

An advanced **TLS threat hunting and anomaly detection** tool built around the **JA4 fingerprint family**.

This project analyzes JA4-based client/server TLS fingerprints, calculates behavioral risk metrics, and produces:

- A detailed CSV report with per-session risk scores.
- A human-readable smart text report with summary and top anomalies.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [How It Works](#how-it-works)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Input CSV Format](#input-csv-format)
- [Sample Dataset](#sample-dataset)
- [Usage](#usage)
- [Output Files](#output-files)
- [Risk Logic Summary](#risk-logic-summary)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Roadmap Ideas](#roadmap-ideas)
- [Author](#author)

---

## Overview

`TLS_Behavioral_Intelligence_Engine.py` reads JA4 telemetry from CSV logs and evaluates each session/flow using a hybrid approach:

1. **Rule-based intelligence scoring** for malware likelihood, stack spoofing, drift, and client-server consistency.
2. **Unsupervised anomaly detection** using Isolation Forest over selected numerical features.

The final result helps SOC, threat hunters, and DFIR teams quickly prioritize suspicious TLS behavior.

---

## Features

- JA4 family support (`ja4`, `ja4_o`, `ja4_r`, `ja4_ro`, `ja4s`, `ja4s_r`)
- Rarity scoring per JA4 pattern
- TLS stack spoofing heuristics (e.g., suspicious TLS 1.3 patterns)
- JA4 raw/sorted drift detection
- Client-server fingerprint consistency checks
- SNI behavior checks (e.g., IP-based or unknown SNI)
- ML anomaly flag (`ML_Anomaly`) powered by Isolation Forest
- Clean CLI execution with output artifacts

---

## How It Works

For each row in your dataset, the engine:

1. Normalizes missing JA4-family fields.
2. Computes **rarity score** based on JA4 frequency and connection count.
3. Applies behavioral heuristics to estimate:
   - malware tendency
   - spoofing behavior
   - library impersonation
   - protocol/stack consistency
4. Calculates:
   - `Risk_Score_Pct`
   - `Alert_Level` (`INFO`, `WARNING`, `HIGH`, `CRITICAL`)
5. Runs Isolation Forest and appends `ML_Anomaly` (0 = normal, 1 = anomaly).

---

## Project Structure

```text
.
├── TLS_Behavioral_Intelligence_Engine.py
├── requirements.txt
├── README.md
└── sample_ja4_log.csv
```

---

## Requirements

- Python 3.8+
- pandas
- numpy
- scikit-learn

Install dependencies from `requirements.txt`.

---

## Installation

```bash
git clone <your-repository-url>
cd TLS-Behavioral-Intelligence-Engine
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

---

## Input CSV Format

### Required Columns

- `server_name` (string)
- `count` (integer)

### JA4 Family Columns (recommended)

- `ja4`
- `ja4_o`
- `ja4_r`
- `ja4_ro`
- `ja4s`
- `ja4s_r`

> If JA4-family columns are missing, the script auto-creates them as empty strings. However, including them improves analysis quality.

### Notes

- Use one row per fingerprint observation/session aggregate.
- Higher `count` values increase behavioral weighting.
- Ensure numeric values in `count` are valid integers.

---

## Sample Dataset

A sample CSV is provided:

- `sample_ja4_log.csv`

You can use it immediately to validate the pipeline.

---

## Usage

Run the engine:

```bash
python3 TLS_Behavioral_Intelligence_Engine.py
```

Then provide path to your CSV when prompted, for example:

```text
[?] Enter the path to your JA4 log file (.csv): sample_ja4_log.csv
```

---

## Output Files

After execution, the script generates:

1. **`Advanced_TLS_Analysis_Report.csv`**
   - Full enriched dataset with risk metrics and ML anomaly flag.

2. **`Security_Smart_Report.txt`**
   - Summary statistics by alert level
   - Top 10 highest-risk sessions with key forensic context

---

## Risk Logic Summary

The final risk score is derived from:

- `malware` contribution (50%)
- `spoofing` contribution (30%)
- `drift` contribution (20%)

`Risk_Score_Pct` is capped at 100 and mapped to:

- `CRITICAL` ≥ 85
- `HIGH` ≥ 65
- `WARNING` ≥ 35
- `INFO` < 35

---

## Troubleshooting

- **File not found**: Ensure you provide the correct path.
- **Not a CSV**: Input must end in `.csv`.
- **Bad `count` values**: Convert non-numeric values to integers.
- **Poor results quality**: Include full JA4 family columns and realistic traffic volume.

---

## Limitations

- Rule thresholds are static and may need tuning for each environment.
- JA4 parsing assumes a specific JA4 string pattern.
- Isolation Forest is unsupervised and may require contamination tuning.
- The engine currently operates on CSV batch input (not streaming).

---

## Roadmap Ideas

- Configurable thresholds via YAML/JSON
- Whitelisting / baseline profiling per environment
- Stream processing mode
- SIEM/SOAR integration exporters
- Unit tests and benchmark datasets

---

## Author

**Alireza Shamloo**

- Email: a.shamloo1414@gmail.com
- LinkedIn: https://linkedin.com/in/alireza-shamloo
- GitHub: https://github.com/mrshamloo

If this project helped you, consider starring the repository and contributing improvements.
