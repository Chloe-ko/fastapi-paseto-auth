You can specify which purpose you would like to use for a PASETO by using the **purpose** parameter in **create_access_token()** or **create_refresh_token()**.

Please read up on PASETO tokens to find out which is the best purpose for your use case, but to put it short:

**Local** purpose means the token will be encrypted using symmetric encryption. Data in the token will not be accessible to people that get the token without also knowing your secret key.\
This is useful if the token is used in an environment where every party that needs access to the token's contents is a secure environment under your control that you can share the secret key with.

**Public** purpose means the token will not be encrypted, and instead will only be signed using your private key.
The data in the key **will be visible to everyone that gets ahold of the key**, and you should not put any confidential or sensitive data into public keys.
The key can then be validated using your public key, which is safe to share with not-trusted parties.


```python hl_lines="16 35-36"
{!../examples/purpose.py!}
```
