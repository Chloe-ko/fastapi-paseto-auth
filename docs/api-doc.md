In here you will find the API for everything exposed in this extension.

### Configuring FastAPI PASETO Auth

**load_config**(callback):\
    This decorator sets the callback function to overwrite state on AuthPASETO class so
    when you initialize an instance in dependency injection default value will be overwritten.

    The callback must be a function that returns a list of tuple or pydantic object.

#
**token_in_denylist_loader**(callback):\
    This decorator sets the callback function that will be called when
    a protected endpoint is accessed and will check if the PASETO has
    been revoked. By default, this callback is not used.

    The callback must be a function that takes `one` argument, which is the decoded PASETO (python dictionary),
    and returns `True` if the token has been revoked, or `False` otherwise.
---
### Protected Endpoint

**paseto_required**(optional: bool = False, fresh: bool = False, refresh_token: bool = False):\
    If you call this function, it will ensure that the requester has a valid access token before
    executing the code below your router. Depending on set options, it might not raise an exception even if the check fails.*

    * Parameters:
        **optional**: Defines whether the check should continue even if no PASETO is found.\
                      (An exception will still always be raised if an invalid one is found.)
        **fresh**: If set to True, requires any PASETO found to be a fresh access token.
        **refresh_token**: If set to True, checks for a refresh token instead of an access token.
    * Returns: None



### Utilities

**create_access_token**(subject, fresh=False, purpose=None, headers=None, expires_time=None, audience=None, user_claims={}):\
    *Create a new access token.*

    * Parameters:
        **subject**: Identifier for who this token is for example id or username from database
        **fresh**: Identify if token is fresh or non-fresh
        **purpose**: Purpose for the PASETO
        **headers**: Valid dict for specifying additional headers in PASETO header section
        **expires_time**: Set the duration of the PASETO
        **audience**: Expected audience in the PASETO
        **user_claims**: Custom claims to include in this token. This data must be dictionary
    * Returns: An encoded access token

**create_refresh_token**(subject, purpose=None, headers=None, expires_time=None, audience=None, user_claims={}):\
    *Creates a new refresh token.*

    * Parameters:
        **subject**: Identifier for who this token is for example id or username from database
        **purpose**: Purpose for the PASETO
        **headers**: Valid dict for specifying additional headers in PASETO header section
        **expires_time**: Set the duration of the PASETO
        **audience**: Expected audience in the PASETO
        **user_claims**: Custom claims to include in this token. This data must be dictionary
    * Returns: An encoded refresh token

**get_token_payload**():\
    *This will return the python dictionary which has all of the claims of the PASETO that is accessing the endpoint.
    If no PASETO is currently present, return `None` instead.*

    * Parameters: None
    * Returns: Dictionary that contains the claims of PASETO

**get_jti**():\
    *Returns the JTI (unique identifier) of an the PASETO that is accessing the endpoint*

    * Parameters: None
    * Returns: String of JTI

**get_subject**()\:
    *This will return the subject of the PASETO that is accessing the endpoint.
    If no PASETO is present, `None` is returned instead.*
