# Shadow AI Detector

A detection framework for identifying unauthorized AI usage across enterprise environments. Built for financial institutions subject to OSFI E-23 and SR 11-7.

## What It Does

- Scans network logs, API calls, and browser extensions for AI tool signatures
- Identifies unauthorized ChatGPT, Claude, Gemini, and Copilot usage
- Maps third-party vendor tools with embedded AI capabilities
- Generates a risk-classified Shadow AI report

## Quick Start

git clone https://github.com/AlBochi/shadow-ai-detector.git
cd shadow-ai-detector
pip install -r requirements.txt
python detect.py --org your-organization

## Sample Detection Report

| Tool | Department | Users | Data Exposure Risk | Status |
|------|-----------|-------|-------------------|--------|
| ChatGPT Free | Marketing | 12 | High | Unauthorized |
| Claude Pro | Risk Team | 3 | Medium | Under Review |
| GitHub Copilot | Engineering | 28 | Low | Approved |

## Regulatory Alignment

- OSFI E-23 Model Inventory (Shadow AI identification)
- SR 11-7 Model Risk Management
- SEC Cybersecurity Disclosure Requirements

## Status

Proof of concept by Saillent. Demonstrates what enterprise-grade Shadow AI detection should look like.

## License

MIT
