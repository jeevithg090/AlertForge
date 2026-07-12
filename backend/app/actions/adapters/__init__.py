"""Action adapters. Mock/simulation adapters ship by default; real adapters
(cloud SG revoke, Okta suspend, EDR isolate) implement the same contract."""
from app.actions.adapters.mock import default_adapters as _mock_adapters


def default_adapters():
    from app.config import settings

    adapters = _mock_adapters()
    if settings.cloudflare_api_token and settings.cloudflare_zone_id:
        from app.actions.adapters.cloudflare import CloudflareBlockIPAdapter

        cfa = CloudflareBlockIPAdapter(
            api_token=settings.cloudflare_api_token,
            zone_id=settings.cloudflare_zone_id,
        )
        adapters = [cfa if a.action_type == "block_ip" else a for a in adapters]
    return adapters


__all__ = ["default_adapters"]
