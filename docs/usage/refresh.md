These are long-lived tokens which can be used to create a new access tokens once an old access token has expired. Refresh tokens cannot access an endpoint that is protected with **paseto_required()**, and access tokens cannot access an endpoint that is protected with **paseto_required(refresh_token=True)**.

Access tokens are marked as fresh if they were generated from the user authenticating with their user credentials, rather than a refresh token. This increases the chance of the authenticating entity actually being the user, rather than an attacker that stole a refresh token.

By utilizing refresh tokens we can reduce the damage that can be done if an access tokens is stolen. However, if an attacker gets ahold of a refresh token they can keep generating new access tokens and access protected endpoints as though they were that user. We can help combat this by using the fresh tokens pattern, discussed in the next section.

For accessing **/refresh** endpoint remember to change the token you send in a request from an **access_token** to a **refresh_token**
    `Authorization: Bearer <refresh_token>`

Here is an example of using access and refresh tokens:

```python hl_lines="35 46"
{!../examples/refresh.py!}
```
