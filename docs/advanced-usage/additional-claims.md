You may want to store additional information in the access token or refresh token that you can later access in the protected views.

This can be done easily by passion additional information as a dictionary to the parameter **user_claims** in the functions **create_access_token()** or **create_refresh_token()**, and the data can be accessed later in a protected endpoint with the **get_token_payload()** function.

Storing data in the tokens can be good for performance.\
If you store data in the tokens, you won't need to look it up from disk/DB next time you need it in a protected endpoint.\
However, you might need to take care of what data you put in the tokens.

**Note**: When using the "public" purpose of PASETO tokens, the data in the token will merely be signed, but not encrypted. This means anyone with access to the token can freely read it's contents.\
Hence, do not store sensitive information in public tokens. Whether you trust local (encrypted) PASETO tokens to keep sensitive information is up to your own discretion.


```python hl_lines="34-35 44"
{!../examples/additional_claims.py!}
```
