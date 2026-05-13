#!/usr/bin/env python3
"""
Saillent Shadow AI Financial Exposure Calculator (SAFE-C)
Quantifies the financial and regulatory exposure of unauthorized AI usage
using the Saillent Shadow Risk Model (SSRM-2).
"""

import json
import math
from datetime import datetime
from collections import defaultdict

class ShadowExposureCalculator:
    """
    Saillent Shadow Risk Model (SSRM-2)
    Calculates financial exposure from Shadow AI using:
    - Data breach probability modeling
    - Regulatory penalty estimation
    - Intellectual property leakage valuation
    - Reputational damage quantification
    """
    
    # Industry benchmark data (2026)
    BREACH_COST_PER_RECORD = {
        "financial": 298,  # USD per record
        "healthcare": 429,
        "technology": 242,
        "retail": 165
    }
    
    REGULATORY_FRAMEWORKS = {
        "OSFI_E23": {"max_penalty": 50_000_000, "probability_weight": 0.15},
        "SR11_7": {"max_penalty": 75_000_000, "probability_weight": 0.12},
        "GDPR": {"max_penalty": 100_000_000, "probability_weight": 0.08},
        "CCPA": {"max_penalty": 25_000_000, "probability_weight": 0.05},
        "PIPEDA": {"max_penalty": 10_000_000, "probability_weight": 0.03}
    }
    
    def __init__(self, organization_name, industry="financial", annual_revenue=1_000_000_000):
        self.org = organization_name
        self.industry = industry
        self.revenue = annual_revenue
        self.shadow_tools = []
    
    def add_shadow_tool(self, name, user_count, data_access_level, departments, 
                        potential_records_exposed=0, has_pii=False, has_financial_data=False):
        """Add a detected Shadow AI tool with exposure parameters."""
        
        # Calculate breach probability using Saillent Exposure Model
        breach_probability = self._calculate_breach_probability(
            user_count, data_access_level, has_pii, has_financial_data
        )
        
        # Calculate financial exposure
        cost_per_record = self.BREACH_COST_PER_RECORD.get(self.industry, 250)
        direct_cost = potential_records_exposed * cost_per_record * breach_probability
        
        # Regulatory penalty estimation
        regulatory_cost = self._estimate_regulatory_penalties(
            has_pii, has_financial_data, breach_probability
        )
        
        # Intellectual property risk
        ip_risk = self._calculate_ip_risk(data_access_level, departments)
        
        # Reputational damage (percentage of annual revenue)
        reputation_impact = self.revenue * breach_probability * 0.03
        
        total_exposure = direct_cost + regulatory_cost + ip_risk + reputation_impact
        
        self.shadow_tools.append({
            "tool_name": name,
            "user_count": user_count,
            "data_access_level": data_access_level,
            "departments": departments,
            "potential_records_exposed": potential_records_exposed,
            "has_pii": has_pii,
            "has_financial_data": has_financial_data,
            "breach_probability_pct": round(breach_probability * 100, 4),
            "direct_cost_exposure": round(direct_cost, 2),
            "regulatory_exposure": round(regulatory_cost, 2),
            "ip_risk_exposure": round(ip_risk, 2),
            "reputation_exposure": round(reputation_impact, 2),
            "total_exposure": round(total_exposure, 2),
            "risk_tier": self._classify_risk(total_exposure)
        })
    
    def _calculate_breach_probability(self, users, access_level, has_pii, has_financial):
        """Saillent Breach Probability Model."""
        base_probability = 0.02  # 2% base probability
        
        # User count multiplier (logarithmic scale)
        user_factor = math.log(users + 1) / math.log(1000) * 0.05
        
        # Data access multiplier
        access_multipliers = {"low": 1.0, "medium": 2.5, "high": 5.0, "critical": 10.0}
        access_factor = access_multipliers.get(access_level, 1.0) * 0.01
        
        # PII and financial data penalties
        pii_factor = 0.03 if has_pii else 0
        financial_factor = 0.04 if has_financial else 0
        
        return min(base_probability + user_factor + access_factor + pii_factor + financial_factor, 0.85)
    
    def _estimate_regulatory_penalties(self, has_pii, has_financial, breach_prob):
        """Estimate potential regulatory penalties across all applicable frameworks."""
        total = 0
        for framework, params in self.REGULATORY_FRAMEWORKS.items():
            if has_pii or has_financial:
                expected_penalty = params["max_penalty"] * breach_prob * params["probability_weight"]
                total += expected_penalty
        return total
    
    def _calculate_ip_risk(self, access_level, departments):
        """Calculate intellectual property leakage risk."""
        ip_multipliers = {"low": 100_000, "medium": 500_000, "high": 2_000_000, "critical": 10_000_000}
        base_ip_risk = ip_multipliers.get(access_level, 100_000)
        
        # High-sensitivity departments
        sensitive_depts = {"R&D", "Legal", "Strategy", "M&A", "Finance", "Risk"}
        dept_multiplier = sum(2.0 for d in departments if d in sensitive_depts)
        
        return base_ip_risk * max(dept_multiplier, 1.0)
    
    def _classify_risk(self, exposure):
        if exposure > 10_000_000: return "CRITICAL"
        elif exposure > 1_000_000: return "HIGH"
        elif exposure > 100_000: return "MEDIUM"
        else: return "LOW"
    
    def generate_exposure_report(self, filepath):
        """Generate complete Shadow AI financial exposure report."""
        total_exposure = sum(t["total_exposure"] for t in self.shadow_tools)
        critical_count = sum(1 for t in self.shadow_tools if t["risk_tier"] == "CRITICAL")
        
        report = {
            "report_type": "Saillent Shadow AI Financial Exposure Report",
            "model": "SSRM-2 (Saillent Shadow Risk Model v2.0)",
            "organization": self.org,
            "industry": self.industry,
            "annual_revenue": self.revenue,
            "generated_at": datetime.now().isoformat(),
            "shadow_tools_detected": len(self.shadow_tools),
            "total_financial_exposure": round(total_exposure, 2),
            "exposure_as_pct_of_revenue": round((total_exposure / self.revenue) * 100, 4) if self.revenue > 0 else 0,
            "critical_risk_tools": critical_count,
            "tools": self.shadow_tools,
            "regulatory_frameworks_assessed": list(self.REGULATORY_FRAMEWORKS.keys()),
            "executive_recommendation": ""
        }
        
        if critical_count > 0:
            report["executive_recommendation"] = f"CRITICAL: {critical_count} Shadow AI tools pose immediate financial risk. Total exposure: ${total_exposure:,.0f}. Initiate emergency governance review within 48 hours."
        elif total_exposure > 1_000_000:
            report["executive_recommendation"] = f"ELEVATED: Shadow AI exposure of ${total_exposure:,.0f} requires governance remediation within 2 weeks."
        else:
            report["executive_recommendation"] = f"MONITORED: Shadow AI exposure within acceptable parameters. Maintain detection cadence."
        
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        
        return report

if __name__ == "__main__":
    print("Saillent Shadow Risk Model (SSRM-2)")
    print("=" * 60)
    
    calc = ShadowExposureCalculator(
        "Confidential Financial Institution",
        industry="financial",
        annual_revenue=2_500_000_000
    )
    
    calc.add_shadow_tool(
        "ChatGPT Free", user_count=340, data_access_level="high",
        departments=["Marketing", "R&D", "Strategy"],
        potential_records_exposed=125000, has_pii=True, has_financial_data=True
    )
    calc.add_shadow_tool(
        "Claude Pro (Unauthorized)", user_count=45, data_access_level="critical",
        departments=["Risk", "Finance", "M&A"],
        potential_records_exposed=89000, has_pii=True, has_financial_data=True
    )
    calc.add_shadow_tool(
        "Gemini Personal", user_count=120, data_access_level="medium",
        departments=["HR", "Legal"],
        potential_records_exposed=34000, has_pii=True, has_financial_data=False
    )
    calc.add_shadow_tool(
        "Midjourney", user_count=28, data_access_level="low",
        departments=["Marketing"],
        potential_records_exposed=1200, has_pii=False, has_financial_data=False
    )
    
    report = calc.generate_exposure_report("shadow_exposure_report.json")
    
    print(f"\n📊 Shadow AI Financial Exposure Report")
    print(f"   Organization: {report['organization']}")
    print(f"   Revenue: ${report['annual_revenue']:,.0f}")
    print(f"   Shadow tools detected: {report['shadow_tools_detected']}")
    print(f"   Total exposure: ${report['total_financial_exposure']:,.0f}")
    print(f"   Exposure as % of revenue: {report['exposure_as_pct_of_revenue']}%")
    print(f"   Critical risk tools: {report['critical_risk_tools']}")
    
    print(f"\n📋 Tool Breakdown:")
    for tool in report["tools"]:
        print(f"   {tool['tool_name']}: ${tool['total_exposure']:,.0f} ({tool['risk_tier']})")
    
    print(f"\n⚠️  {report['executive_recommendation']}")
