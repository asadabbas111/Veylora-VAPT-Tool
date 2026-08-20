import logging
import smtplib
from email.message import EmailMessage

from app.config import settings

logger = logging.getLogger(__name__)


def send_otp_email(to_email: str, otp: str) -> bool:
    """Send a verification OTP by email.

    When EMAIL_ENABLED is False the code is only logged for the console and the
    caller is expected to surface it in dev mode (settings.DEV_OTP_RETURN).
    """
    if not settings.EMAIL_ENABLED:
        logger.warning("[DEV] Email disabled - OTP for %s: %s", to_email, otp)
        return False

    msg = EmailMessage()
    msg["Subject"] = "Your verification code"
    msg["From"] = settings.SMTP_FROM or settings.SMTP_USER
    msg["To"] = to_email
    msg.set_content(
        f"Your verification code is {otp}\n\n"
        "It expires in a few minutes. Do not share it with anyone."
        "\n\nAI Autonomous Vulnerability Assessment Platform"
    )
    try:
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=20) as server:
            server.starttls()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception:  # pragma: no cover - depends on external SMTP
        logger.exception("Failed to send email to %s", to_email)
        return False