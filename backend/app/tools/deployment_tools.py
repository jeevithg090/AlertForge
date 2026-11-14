"""Recent deployments tool."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.tools.registry import tool


@tool(
    name="get_recent_deployments",
    description="Get list of deployments made in the past N hours. Use to correlate incidents with recent code changes.",
    parameters={
        "type": "object",
        "properties": {
            "environment": {"type": "string", "enum": ["production", "staging", "all"]},
            "hours_back": {"type": "integer", "default": 6},
        },
        "required": [],
    },
)
async def get_recent_deployments(environment: str = "production", hours_back: int = 6) -> dict:
    return _mock_deployments(environment, hours_back)


def _mock_deployments(environment, hours_back):
    now = datetime.now(timezone.utc)
    deployments = [
        {
            "service": "checkout-service",
            "version": "v2.4.0",
            "previous_version": "v2.3.9",
            "deployed_at": (now - timedelta(hours=2)).isoformat(),
            "deployed_by": "ci-pipeline",
            "environment": environment,
            "commit": "a1b2c3d",
            "commit_message": "feat: add cart recommendation engine",
            "files_changed": [
                "checkout/services/cart_service.py",
                "checkout/models/recommendation.py",
                "checkout/api/v2/cart.py",
            ],
            "status": "success",
        },
        {
            "service": "payment-gateway",
            "version": "v1.8.2",
            "previous_version": "v1.8.1",
            "deployed_at": (now - timedelta(hours=4)).isoformat(),
            "deployed_by": "ci-pipeline",
            "environment": environment,
            "commit": "e4f5g6h",
            "commit_message": "fix: retry logic for Stripe webhook",
            "files_changed": ["payment/webhooks/stripe.py"],
            "status": "success",
        },
        {
            "service": "user-auth",
            "version": "v3.1.0",
            "previous_version": "v3.0.5",
            "deployed_at": (now - timedelta(hours=5)).isoformat(),
            "deployed_by": "ci-pipeline",
            "environment": environment,
            "commit": "i7j8k9l",
            "commit_message": "feat: OAuth2 PKCE flow support",
            "files_changed": ["auth/oauth/pkce.py", "auth/config.py"],
            "status": "success",
        },
    ]
    return {
        "environment": environment,
        "hours_back": hours_back,
        "deployments": deployments,
        "count": len(deployments),
    }
