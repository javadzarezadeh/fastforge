import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class SMSService(ABC):
    @abstractmethod
    def send_otp(self, phone_number: str, otp: str) -> bool:
        pass


class MockSMSService(SMSService):
    def send_otp(self, phone_number: str, otp: str) -> bool:
        logger.info(f"Mock SMS: Sending OTP {otp} to {phone_number}")
        return True
