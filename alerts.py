import smtplib
import sys
import threading
from email.mime.text import MIMEText
from plyer import notification

# Override threading excepthook to gracefully handle failures from plyer's internal balloon_tip thread
def _silent_excepthook(args):
    if "Shell_NotifyIconW failed" in str(args.exc_value):
        # Suppress tracebacks from plyer in headless shell environments
        return
    # Fall back to standard error printing
    sys.stderr.write(f"Exception in thread {args.thread.name}: {args.exc_value}\n")

threading.excepthook = _silent_excepthook

def send_desktop_notification(title: str, message: str):
    """Dispatches a native desktop notification."""
    try:
        notification.notify(
            title=title,
            message=message,
            app_name="DataShield DLP",
            timeout=5
        )
    except Exception as e:
        print(f"Warning: Desktop notification dispatch failed: {e}", file=sys.stderr)

def send_email_alert(smtp_config: dict, subject: str, body: str):
    """
    Dispatches a security email alert using the configured SMTP settings.
    """
    if not smtp_config or not smtp_config.get("host") or not smtp_config.get("recipient"):
        return
        
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = smtp_config.get("sender", "datashield-alerts@security.local")
        msg["To"] = smtp_config["recipient"]
        
        host = smtp_config["host"]
        port = int(smtp_config.get("port", 25))
        
        server = smtplib.SMTP(host, port, timeout=10)
        
        try:
            server.starttls()
        except Exception:
            pass
            
        username = smtp_config.get("username")
        password = smtp_config.get("password")
        if username and password:
            server.login(username, password)
            
        server.send_message(msg)
        server.quit()
        
    except Exception as e:
        print(f"Warning: SMTP email alert dispatch failed: {e}", file=sys.stderr)
