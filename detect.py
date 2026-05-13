#!/usr/bin/env python3
"""
Shadow AI Detector — Saillent
Detects unauthorized AI tool usage across enterprise environments by scanning
DNS logs, firewall exports, and browser extension manifests.
Generates OSFI E-23 / SR 11-7 compliant Shadow AI risk reports.
"""

import json
import argparse
import re
from datetime import datetime, timedelta
from collections import defaultdict

# Known AI tool signatures — domains, API endpoints, browser extension IDs
AI_SIGNATURES = {
    "ChatGPT": {
        "domains": ["chat.openai.com", "api.openai.com", "chatgpt.com"],
        "extensions": ["chrome://extensions/chatgpt"],
        "risk_level": "HIGH",
        "data_exposure": "Prompts may contain PII, financial data, or proprietary information"
    },
    "Claude": {
        "domains": ["claude.ai", "api.anthropic.com"],
        "extensions": [],
        "risk_level": "HIGH",
        "data_exposure": "Document uploads may violate data residency requirements"
    },
    "Gemini": {
        "domains": ["gemini.google.com", "generativelanguage.googleapis.com"],
        "extensions": [],
        "risk_level": "MEDIUM",
        "data_exposure": "Integrated with Google Workspace — data may cross organizational boundaries"
    },
    "GitHub Copilot": {
        "domains": ["copilot.github.com", "api.github.com/copilot"],
        "extensions": [],
        "risk_level": "MEDIUM",
        "data_exposure": "Code snippets may expose proprietary algorithms or API keys"
    },
    "Perplexity": {
        "domains": ["perplexity.ai", "api.perplexity.ai"],
        "extensions": [],
        "risk_level": "MEDIUM",
        "data_exposure": "Search queries may reveal strategic intent or M&A activity"
    },
    "Jasper": {
        "domains": ["jasper.ai", "api.jasper.ai"],
        "extensions": [],
        "risk_level": "LOW",
        "data_exposure": "Marketing content generation — lower sensitivity"
    },
    "Midjourney": {
        "domains": ["midjourney.com", "cdn.midjourney.com"],
        "extensions": [],
        "risk_level": "LOW",
        "data_exposure": "Image generation — may reveal branding or product concepts"
    }
}

def parse_dns_logs(logfile):
    """Parse DNS query logs for AI tool domain hits."""
    detections = []
    try:
        with open(logfile) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for tool_name, sig in AI_SIGNATURES.items():
                    for domain in sig["domains"]:
                        if domain in line.lower():
                            detections.append({
                                "tool": tool_name,
                                "domain": domain,
                                "risk_level": sig["risk_level"],
                                "data_exposure": sig["data_exposure"],
                                "raw_log": line[:200]
                            })
    except FileNotFoundError:
        print(f"   ⚠️  Log file not found: {logfile}")
    return detections

def generate_report(detections, org_name, scan_period_days=90):
    """Generate Shadow AI risk report."""
    tool_counts = defaultdict(int)
    dept_counts = defaultdict(lambda: defaultdict(int))
    
    for d in detections:
        tool_counts[d["tool"]] += 1
    
    high_risk = [d for d in detections if d["risk_level"] == "HIGH"]
    medium_risk = [d for d in detections if d["risk_level"] == "MEDIUM"]
    
    report = {
        "report_type": "Shadow AI Detection Report",
        "framework": "OSFI E-23 / SR 11-7",
        "organization": org_name,
        "scan_period_days": scan_period_days,
        "generated_at": datetime.now().isoformat(),
        "executive_summary": {
            "total_detections": len(detections),
            "unique_tools_detected": len(tool_counts),
            "high_risk_events": len(high_risk),
            "medium_risk_events": len(medium_risk),
            "assessment": "CRITICAL" if len(high_risk) > 0 else "ELEVATED" if len(medium_risk) > 10 else "MONITORED"
        },
        "detections": detections[:100],  # Cap at 100 for readability
        "tool_summary": {tool: {"count": count, "risk": AI_SIGNATURES[tool]["risk_level"]} 
                        for tool, count in sorted(tool_counts.items(), key=lambda x: -x[1])},
        "regulatory_implications": [
            "OSFI E-23: Unauthorized AI tools must be inventoried and risk-assessed",
            "SR 11-7: Shadow AI constitutes unmanaged model risk",
            "SEC: Material AI usage may require disclosure",
            "CFPB: Consumer-impacting AI tools require fair lending review"
        ],
        "recommended_actions": []
    }
    
    if high_risk:
        report["recommended_actions"].append({
            "priority": "IMMEDIATE",
            "action": f"Initiate governance review for {len(high_risk)} high-risk Shadow AI events",
            "timeline": "Within 48 hours"
        })
    
    report["recommended_actions"].append({
        "priority": "SHORT_TERM",
        "action": f"Implement approved AI tool registry and block {len(tool_counts)} unauthorized tools",
        "timeline": "Within 2 weeks"
    })
    
    report["recommended_actions"].append({
        "priority": "ONGOING",
        "action": "Deploy continuous Shadow AI monitoring with weekly executive reports",
        "timeline": "Within 30 days"
    })
    
    return report

def main():
    parser = argparse.ArgumentParser(description="Saillent Shadow AI Detector")
    parser.add_argument("--dns-logs", help="Path to DNS query logs", default=None)
    parser.add_argument("--firewall-logs", help="Path to firewall export", default=None)
    parser.add_argument("--org", help="Organization name", default="Confidential Client")
    parser.add_argument("--output", help="Output JSON file", default="shadow_ai_report.json")
    args = parser.parse_args()
    
    print(f"\n🕵️  Saillent Shadow AI Detector")
    print(f"   Organization: {args.org}")
    print(f"   Framework: OSFI E-23 / SR 11-7\n")
    
    all_detections = []
    
    if args.dns_logs:
        print(f"   Scanning DNS logs: {args.dns_logs}")
        detections = parse_dns_logs(args.dns_logs)
        all_detections.extend(detections)
        print(f"   ✅ DNS scan complete: {len(detections)} events\n")
    
    if args.firewall_logs:
        print(f"   Scanning firewall logs: {args.firewall_logs}")
        detections = parse_dns_logs(args.firewall_logs)
        all_detections.extend(detections)
        print(f"   ✅ Firewall scan complete: {len(detections)} events\n")
    
    if not args.dns_logs and not args.firewall_logs:
        # Demo mode — generate sample data
        print("   ℹ️  No log files provided. Running in DEMO mode with sample data.\n")
        sample_domains = [
            "chat.openai.com query from 10.0.1.42",
            "api.anthropic.com query from 10.0.2.17",
            "gemini.google.com query from 10.0.3.8",
            "chat.openai.com query from 10.0.1.55",
            "copilot.github.com query from 10.0.4.12"
        ]
        for line in sample_domains:
            for tool_name, sig in AI_SIGNATURES.items():
                for domain in sig["domains"]:
                    if domain in line:
                        all_detections.append({
                            "tool": tool_name,
                            "domain": domain,
                            "risk_level": sig["risk_level"],
                            "data_exposure": sig["data_exposure"],
                            "raw_log": line
                        })
    
    report = generate_report(all_detections, args.org)
    
    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"📊 Shadow AI Report Summary")
    print(f"   Total detections: {report['executive_summary']['total_detections']}")
    print(f"   Unique tools: {report['executive_summary']['unique_tools_detected']}")
    print(f"   🔴 High risk: {report['executive_summary']['high_risk_events']}")
    print(f"   🟡 Medium risk: {report['executive_summary']['medium_risk_events']}")
    print(f"   Assessment: {report['executive_summary']['assessment']}")
    print(f"   Report saved: {args.output}\n")
    
    print("📋 Recommended Actions:")
    for action in report["recommended_actions"]:
        print(f"   [{action['priority']}] {action['action']}")

if __name__ == "__main__":
    main()
