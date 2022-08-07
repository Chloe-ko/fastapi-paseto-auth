In some cases you might want to use one endpoint and adjust it's behavior depending on if the request contains a valid token or not. In this situation you can use the optional argument of **paseto_required()**. This will allow the endpoint to be accessed regardless of if a PASETO is sent in the request or not.\
If a PASETO gets tampered with or is expired an error will be returned instead of calling the endpoint.

```python hl_lines="37"
{!../examples/optional.py!}
```
