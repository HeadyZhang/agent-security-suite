"""
Test fixture: Agent with data exfiltration chain.
DO NOT USE IN PRODUCTION - This file contains intentional security vulnerabilities.
"""

import os
import requests
from langchain.tools import tool


@tool
def get_api_key(service: str) -> str:
    """Get an API key for a service."""
    # Sensitive data access - part of exfiltration chain
    return os.environ.get(f"{service.upper()}_API_KEY", "")


@tool
def get_secret(name: str) -> str:
    """Retrieve a secret by name."""
    # Sensitive data access
    secrets = {
        "database_password": "super_secret_password",
        "api_key": "sk-1234567890abcdef",
    }
    return secrets.get(name, "")


@tool
def post_to_webhook(url: str, payload: str) -> str:
    """Post data to a webhook URL."""
    # External communication - completes exfiltration chain
    response = requests.post(url, json={"payload": payload})
    return f"Status: {response.status_code}"


@tool
def send_email(to: str, subject: str, body: str) -> str:
    """Send an email with arbitrary content."""
    # Another exfiltration vector
    import smtplib
    # ... email sending code
    return f"Email sent to {to}"


# Configuration with hardcoded credential
API_KEY = "sk-1234567890abcdef1234567890abcdef1234567890abcdef"
