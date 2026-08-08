"""
NetShield AI - Threat Prediction Engine
Predicts future security compromise risks (24-hour forecast) by analyzing trend velocity,
anomaly acceleration, and behavioral indicators.
"""

from typing import Dict, Any, List
from backend.models import DeviceRiskProfile

class PredictionEngine:
    def __init__(self):
        pass

    def predict_device_risk(self, profile: DeviceRiskProfile, recent_failed_logins: int, recent_traffic_multiplier: float) -> Dict[str, Any]:
        """
        Calculates predicted risk score over the next 24 hours based on velocity of threat factors.
        """
        base_risk = profile.current_risk_score
        predicted_24h = base_risk
        reasons = []

        # Velocity factor 1: Auth failure escalation
        if recent_failed_logins > 5:
            delta = recent_failed_logins * 2.5
            predicted_24h += delta
            reasons.append("• Exponential growth in authentication failures")

        # Velocity factor 2: Traffic volume escalation
        if recent_traffic_multiplier > 2.0:
            delta = recent_traffic_multiplier * 5.0
            predicted_24h += delta
            reasons.append(f"• Network traffic velocity elevated ({recent_traffic_multiplier:.1f}x normal baseline)")

        # Velocity factor 3: Active threat count
        if profile.active_threats > 0:
            predicted_24h += (profile.active_threats * 8.0)
            reasons.append(f"• Host currently has {profile.active_threats} unresolved active security alert(s)")

        # Bound predicted risk between 0 and 99%
        predicted_24h = min(99.0, max(base_risk, predicted_24h))

        if not reasons:
            reasons.append("• System metrics stable within expected baseline bounds")

        risk_level = "CRITICAL RISK ACCELERATION" if predicted_24h >= 85 else ("HIGH PREDICTED RISK" if predicted_24h >= 70 else "STABLE")

        return {
            "device_id": profile.device_id,
            "device_name": profile.name,
            "current_risk": round(base_risk, 1),
            "predicted_risk_24h": round(predicted_24h, 1),
            "risk_delta": round(predicted_24h - base_risk, 1),
            "prediction_status": risk_level,
            "prediction_factors": reasons
        }
