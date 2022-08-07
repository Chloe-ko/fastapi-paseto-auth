Because *fastapi-paseto-auth* configures your setting via a class state that applies across all instances of the class, you only need to make sure to call **load_config**(callback) before declaring any endpoint. Thanks to `FastAPI` when you make an endpoint from `APIRouter` it will actually work as if everything was the same single app.

So you only need to define **load_config**(callback) where your `FastAPI` instance is created or you can import it where you include all the routers. 

## An example file structure

Let's say you have a file structure like this:

```
.
├── multiple_files
│   ├── __init__.py
│   ├── app.py
│   └── routers
│       ├── __init__.py
│       ├── items.py
│       └── users.py
```

Here an example of `app.py`

```python
{!../examples/multiple_files/app.py!}
```

Here an example of `users.py`

```python
{!../examples/multiple_files/routers/users.py!}
```

Here an example of `items.py`

```python
{!../examples/multiple_files/routers/items.py!}
```
