The fresh tokens pattern is built into this extension. This pattern is very simple, you can choose to mark some access tokens as fresh and other as a non-fresh tokens, and use the **paseto_required(fresh=True)** function to only allows fresh tokens to access the certain endpoint.

This is useful for allowing the fresh tokens to do some critical things (such as update user information), as you need to login using your user credentials again to get a fresh token.\
Utilizing Fresh tokens in conjunction with refresh tokens can lead to a more secure site, without creating a bad user experience by making users constantly re-authenticate.

Here is an example of how you could utilize refresh tokens with the fresh token pattern:

```python hl_lines="39 82"
{!../examples/freshness.py!}
```
