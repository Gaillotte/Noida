"""KMIP exception hierarchy."""
from .enums import ResultReason


class KMIPError(Exception):
    """Base class for all KMIP errors."""
    reason: int = ResultReason.GeneralFailure

    def __init__(self, message: str = "", reason: int = None):
        super().__init__(message)
        if reason is not None:
            self.reason = reason
        self.message = message


class ItemNotFound(KMIPError):
    reason = ResultReason.ItemNotFound


class AuthenticationFailed(KMIPError):
    reason = ResultReason.AuthenticationNotSuccessful


class NotAuthorized(KMIPError):
    reason = ResultReason.PermissionDenied


class InvalidMessage(KMIPError):
    reason = ResultReason.InvalidMessage


class InvalidField(KMIPError):
    reason = ResultReason.InvalidField


class OperationNotSupported(KMIPError):
    reason = ResultReason.OperationNotSupported


class CryptographicFailure(KMIPError):
    reason = ResultReason.CryptographicFailure


class IllegalOperation(KMIPError):
    reason = ResultReason.IllegalOperation


class NotExtractable(KMIPError):
    reason = ResultReason.NotExtractable


class MissingData(KMIPError):
    reason = ResultReason.MissingData


class GeneralFailure(KMIPError):
    reason = ResultReason.GeneralFailure
