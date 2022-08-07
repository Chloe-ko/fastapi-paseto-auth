You can also change the expiry time for a token via parameter **expires_time** in the **create_access_token()** or **create_refresh_token()** function. This takes a *datetime.timedelta*, *datetime.datetime*, *integer*, or even *boolean* and overrides the `authpaseto_access_token_expires` and `authpaseto_refresh_token_expires` settings. This can be useful if you have different use cases for different tokens.

```python
@app.post('/create-dynamic-token')
def create_dynamic_token(Authorize: AuthPASETO = Depends()):
    expires = datetime.timedelta(days=1)
    token = Authorize.create_access_token(subject="test",expires_time=expires)
    return {"token": token}
```

You can even disable expiration by setting **expires_time** to *False*:

```python
@app.post('/create-token-disable')
def create_dynamic_token(Authorize: AuthPASETO = Depends()):
    token = Authorize.create_access_token(subject="test",expires_time=False)
    return {"token": token}
```
