"""
Email service interface and implementations.

This module provides an interface for sending emails with a mock implementation
that logs emails instead of sending them, similar to the SMS service approach.
"""

import logging
from abc import ABC, abstractmethod
from typing import List

from .config import Config


class EmailService(ABC):
    """Abstract base class for email services"""

    @abstractmethod
    async def send_email(self, to_emails: List[str], subject: str, body: str):
        """Send an email to the specified recipients"""
        pass


class MockEmailService(EmailService):
    """Mock email service that logs emails instead of sending them"""

    async def send_email(self, to_emails: List[str], subject: str, body: str):
        """
        Log the email instead of sending it.

        Args:
            to_emails: List of recipient email addresses
            subject: Email subject
            body: Email body content
        """
        logging.info(
            f"Mock Email: Sending email to {to_emails} with subject '{subject}'"
        )
        print(
            f"MOCK EMAIL SENT:\n"
            f"To: {', '.join(to_emails)}\n"
            f"Subject: {subject}\n"
            f"Body: {body}\n"
        )


def get_email_service() -> EmailService:
    """
    Dependency function to get the appropriate email service based on configuration.

    Returns:
        An instance of the configured email service
    """
    email_service_type = Config.EMAIL_SERVICE_TYPE.lower()

    if email_service_type == "mock":
        return MockEmailService()
    else:
        # Default to mock for safety
        logging.warning(
            f"Unknown email service type '{email_service_type}', defaulting to mock"
        )
        return MockEmailService()
