import smtplib
from email.mime.text import MIMEText
import sys

def send_test_email(subject, body, port=1025):
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = 'sender@test.local'
    msg['To'] = 'recipient@test.local'
    
    print(f"Connecting to localhost:{port}...")
    try:
        with smtplib.SMTP('127.0.0.1', port, timeout=10) as server:
            print("Sending message...")
            response = server.sendmail('sender@test.local', ['recipient@test.local'], msg.as_string())
            print(f"Success! Response: {response}")
    except smtplib.SMTPResponseException as e:
        print(f"SMTP Error: Code {e.code}, Message: {e.obj}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python test_smtp.py [safe|risky|medium]")
        sys.exit(1)
        
    mode = sys.argv[1]
    if mode == "safe":
        send_test_email("Safe Team Sync", "Hi team, let's sync up tomorrow at 10 AM.")
    elif mode == "risky":
        send_test_email("Q3 Employee Records", "Aadhaar: 1234 5678 9012\nPAN: ABCDE1234F\nEmail: test@test.com\nPhone: 9876543210")
    elif mode == "medium":
        send_test_email("Invoice Verification", "Please pay card: 4111111111111111")
