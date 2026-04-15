"""
Alert system — webhook and email notifications for phishing detections.

Sends HTTP POST to configured webhook URLs, and/or SMTP email messages,
when a phishing event is detected.
Fire-and-forget: errors are logged but never propagate to the caller.
"""

import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Timeout for webhook HTTP requests (seconds)
WEBHOOK_TIMEOUT = 10.0

# SMTP configuration (via environment variables)
SMTP_HOST = os.environ.get("SMTP_HOST", "localhost")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "alerts@phishing-guard.local")


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


async def send_email_alert(
    *,
    org_id: str,
    event: dict,
) -> None:
    """Send email alerts for a phishing event to all configured recipients.

    Fetches enabled email configs for the org and sends an SMTP message to each.
    Errors are logged but do not raise exceptions.

    Args:
        org_id: Organisation that owns the event.
        event: Dict with event details (as returned by log_event()).
    """
    from db import get_alert_configs

    try:
        configs = await get_alert_configs(org_id, "email")
    except Exception as exc:
        logger.warning(f"Failed to fetch email configs for {org_id}: {exc}")
        return

    if not configs:
        return

    payload = _build_payload(org_id, event)
    subject, body = _build_email(payload)

    for config in configs:
        recipient = config["endpoint"]
        try:
            _send_smtp(recipient, subject, body)
            logger.info(f"Email alert sent to {recipient} for org {org_id}")
        except Exception as exc:
            logger.warning(f"Email alert failed for {recipient}: {exc}")


def _send_smtp(recipient: str, subject: str, body: str) -> None:
    """Send a plain-text email via SMTP (synchronous, called from async context)."""
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = recipient
    msg["Subject"] = subject
    msg.set_content(body)

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        if SMTP_USER and SMTP_PASSWORD:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASSWORD)
        smtp.send_message(msg)


def _build_email(payload: dict) -> tuple[str, str]:
    """Build email subject and plain-text body from the alert payload."""
    event = payload["event"]
    org_id = payload["org_id"]
    url = event.get("url") or ""
    email_subject = event.get("email_subject") or ""
    confidence = event.get("confidence", 0)
    created_at = event.get("created_at") or ""

    target = url or email_subject or "(unknown)"
    subject = f"[PhishingGuard] Phishing detectado — {org_id}"

    lines = [
        f"Alerta de phishing detectado para a organização: {org_id}",
        "",
        f"  Alvo      : {target}",
        f"  Confiança : {confidence}%",
        f"  Tipo      : {event.get('event_type', '')}",
        f"  Label     : {event.get('label', '')}",
        f"  Detectado : {created_at}",
        f"  Evento ID : {event.get('id', '')}",
        "",
        "Este é um alerta automático do sistema PhishingGuard.",
    ]
    body = "\n".join(lines)
    return subject, body


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
            "user_email": event.get("user_email"),
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
