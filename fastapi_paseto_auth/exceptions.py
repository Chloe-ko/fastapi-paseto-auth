class AuthPASETOException(Exception):
    """
    Base except which all fastapi_paseto_auth errors extend
    """

    pass


class InvalidHeaderError(AuthPASETOException):
    """
    An error getting paseto in header or paseto header information from a request
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class PASETODecodeError(AuthPASETOException):
    """
    An error decoding a PASETO
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class InvalidPASETOVersionError(AuthPASETOException):
    """
    Error raised if the version of the PASETO is not supported
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class InvalidPASETOArgumentError(AuthPASETOException):
    """
    Error raised if PASETOs get checked with unfulfillable arguments
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class InvalidPASETOPurposeError(AuthPASETOException):
    """
    Error raised if the purpose of the PASETO is not supported
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class MissingTokenError(AuthPASETOException):
    """
    Error raised when token not found
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class RevokedTokenError(AuthPASETOException):
    """
    Error raised when a revoked token attempt to access a protected endpoint
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class AccessTokenRequired(AuthPASETOException):
    """
    Error raised when a valid, non-access PASETO attempt to access an endpoint
    protected by paseto_required, paseto_optional, fresh_paseto_required
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class RefreshTokenRequired(AuthPASETOException):
    """
    Error raised when a valid, non-refresh PASETO attempt to access an endpoint
    protected by paseto_refresh_token_required
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class FreshTokenRequired(AuthPASETOException):
    """
    Error raised when a valid, non-fresh PASETO attempt to access an endpoint
    protected by fresh_paseto_required
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message
