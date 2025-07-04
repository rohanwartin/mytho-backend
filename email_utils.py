import os
import ssl
import urllib.request
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Email, To, Content
from jinja2 import Environment, FileSystemLoader
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Set up Jinja2 environment
env = Environment(loader=FileSystemLoader("templates"))

# DEV MODE SSL BYPASS
if os.getenv("ENV").lower() == "development":
    print("[INFO] Running in development mode. SSL verification is disabled.")

    # Disable SSL certificate verification globally
    ssl._create_default_https_context = ssl._create_unverified_context

    # Patch urllib globally for sendgrid internals
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl._create_unverified_context())
    )
    urllib.request.install_opener(opener)


# Render email template
def render_template(name: str, otp: str) -> str:
    template = env.get_template("otp_email.html")
    return template.render(name=name, otp=otp)


# Send email via SendGrid
def send_email_with_sendgrid(to_email: str, subject: str, html_content: str):
    try:
        message = Mail(
            from_email=Email(os.getenv("SENDGRID_FROM_EMAIL"), os.getenv("SENDGRID_FROM_NAME")),
            to_emails=To(to_email),
            subject=subject,
            html_content=Content("text/html", html_content)
        )
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        response = sg.send(message)
        print("Email Sent:", response.status_code)
        return response.status_code
    except Exception as e:
        print("SendGrid error:", e)
        raise
