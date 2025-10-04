import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class SMSService(ABC):
    @abstractmethod
    def send_otp(self, phone_number: str, otp: str) -> bool:
        """
        Send OTP to the specified phone number

        Args:
            phone_number: The phone number to send OTP to
            otp: The OTP code to send

        Returns:
            bool: True if SMS was sent successfully, False otherwise
        """
        pass


class MockSMSService(SMSService):
    def send_otp(self, phone_number: str, otp: str) -> bool:
        """
        Mock implementation that logs OTP to console instead of sending real SMS

        Args:
            phone_number: The phone number to send OTP to
            otp: The OTP code to send

        Returns:
            bool: Always returns True as it just logs the OTP
        """
        logger.info(f"Mock SMS: Sending OTP {otp} to {phone_number}")
        return True


def get_sms_service() -> SMSService:
    """
    Factory function to get appropriate SMS service based on environment

    Returns:
        SMSService: An instance of the configured SMS service
    """
    # In a real implementation, this could return different services based on environment
    # For example, a real SMS service in production and MockSMSService in development
    return MockSMSService()
