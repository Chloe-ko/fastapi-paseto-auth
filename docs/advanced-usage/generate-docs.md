It feels incomplete if there is no documentation because *fastapi-paseto-auth* uses starlette requests directly to get headers, you must manually generate the documentation. Thanks to `FastAPI` you can generate doc easily via `Extending OpenAPI`.

Here is an example to generate the doc:

```python hl_lines="37 57-65 69 71-78"
{!../examples/generate_doc.py!}
```
