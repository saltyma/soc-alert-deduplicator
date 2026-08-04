"""Application-specific exceptions with safe, user-facing messages."""


class DeduplicatorError(Exception):
    """Base class for expected operational failures."""


class ConfigurationError(DeduplicatorError):
    """Raised when the configuration file is missing or invalid."""


class AlertInputError(DeduplicatorError):
    """Raised when alert input cannot be read or validated."""


class IncidentOutputError(DeduplicatorError):
    """Raised when incident output cannot be written safely."""
