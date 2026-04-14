from app.models import SecurityEvent


class ResponsePlanner:
    def recommend(self, incident_type: str, risk_score: float, event: SecurityEvent) -> str:
        recommendations = {
            "credential_bruteforce": (
                "Temporarily block source IP, require password reset for impacted account, "
                "and enforce multi-factor authentication"
            ),
            "privilege_escalation": (
                "Revert IAM policy change, disable modified principal, and open analyst review"
            ),
            "data_exfiltration": (
                "Revoke access token, isolate service account, and inspect destination resource"
            ),
            "public_resource_exposure": (
                "Re-apply private ACL immediately and run bucket/object exposure audit"
            ),
            "resource_hijack": (
                "Stop newly created compute resources, rotate credentials, and review billing anomalies"
            ),
        }

        base_recommendation = recommendations.get(
            incident_type,
            "Create analyst ticket, capture volatile context, and continue monitoring",
        )

        if risk_score >= 80:
            return f"High urgency: {base_recommendation}. Execute within 5 minutes with human approval."
        if risk_score >= 60:
            return f"Medium urgency: {base_recommendation}. Execute within 30 minutes."

        return f"Low urgency: {base_recommendation}. Track for correlation unless repeated."
