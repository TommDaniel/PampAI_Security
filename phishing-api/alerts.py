"""
Alert system — webhook notifications for phishing detections.

Sends HTTP POST to configured webhook URLs when a phishing event is detected.
Fire-and-forget: errors are logged but never propagate to the caller.
"""

import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Timeout for webhook HTTP requests (seconds)
WEBHOOK_TIMEOUT = 10.0


async def send_webhook_alert(
    *,
    org_id: str,
    event: dict,
) -> None:
    """Send webhook alerts for a phishing event to all configured endpoints.

    Fetches enabled webhook configs for the org and fires a POST to each.
    Errors are logged but do not raise exceptions.

    Args:
        org_id: Organisation that owns the event.
        event: Dict with event details (as returned by log_event()).
    """
    from db import get_alert_configs

    try:
        configs = await get_alert_configs(org_id, "webhook")
    except Exception as exc:
        logger.warning(f"Failed to fetch webhook configs for {org_id}: {exc}")
        return

    if not configs:
        return

    payload = _build_payload(org_id, event)

    async with httpx.AsyncClient(timeout=WEBHOOK_TIMEOUT) as client:
        for config in configs:
            url = config["endpoint"]
            try:
                response = await client.post(url, json=payload)
                logger.info(
                    f"Webhook alert sent to {url} — status {response.status_code}"
                )
            except Exception as exc:
                logger.warning(f"Webhook alert failed for {url}: {exc}")


def _build_payload(org_id: str, event: dict) -> dict:
    """Build the webhook POST payload from the event dict."""
    created_at = event.get("created_at")
    if created_at is not None and hasattr(created_at, "isoformat"):
        created_at = created_at.isoformat()

    return {
        "alert_type": "phishing_detected",
        "org_id": org_id,
        "event": {
            "id": event.get("id"),
            "event_type": event.get("event_type"),
            "is_phishing": event.get("is_phishing"),
            "confidence": event.get("confidence"),
            "label": event.get("label"),
            "url": event.get("url"),
            "email_subject": event.get("email_subject"),
            "email_sender": event.get("email_sender"),
            "source": event.get("source"),
            "created_at": created_at,
        },
    }
