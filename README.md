<h1 align="left" style="margin-bottom: 20px; font-weight: 500; font-size: 50px; color: black;">
  FastAPI PASETO Auth
</h1>

![Tests](https://github.com/Chloe-ko/fastapi-paseto-auth/workflows/Tests/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/Chloe-ko/fastapi-paseto-auth/badge.svg?branch=master)](https://coveralls.io/github/Chloe-ko/fastapi-paseto-auth?branch=master)
[![PyPI version](https://badge.fury.io/py/fastapi-paseto-auth.svg)](https://badge.fury.io/py/fastapi-paseto-auth)
[![Downloads](https://static.pepy.tech/personalized-badge/fastapi-paseto-auth?period=total&units=international_system&left_color=grey&right_color=brightgreen&left_text=Downloads)](https://pepy.tech/project/fastapi-paseto-auth)
---

**Documentation**: <a href="https://chloe-ko.github.io/fastapi-paseto-auth" target="_blank">https://chloe-ko.github.io/fastapi-paseto-auth</a>

**Source Code**: <a href="https://github.com/Chloe-ko/fastapi-paseto-auth" target="_blank">https://github.com/Chloe-ko/fastapi-paseto-auth</a>

---

FastAPI extension that provides PASETO (**P**lastform-**A**gnostic **SE**curity **TO**kens) Auth support\
PASETO are a simpler, yet more secure alternative to JWTs.

If you were familiar with flask-jwt-extended or fastapi-jwt-auth this extension suitable for you, as this is forked from fastapi-jwt-auth which in turn used flask-jwt-extended as motivation

## Features
- Access tokens and refresh tokens
- Freshness Tokens
- Revoking Tokens
- Support for adding custom claims to Tokens
- Built-in Base64 Encoding of Tokens
- Custom token types

## Installation
The easiest way to start working with this extension with pip

```bash
pip install fastapi-paseto-auth
```

## Roadmap
- Support for WebSocket authorization

## FAQ
- **Where's support for tokens in cookies?**\
I mostly forked fastapi-jwt-auth because I needed a library to use for authentication using PASETO tokens in my private FastAPI Application. Which is why I only kept the functionality that I personally required.\
Personally, I'm not a fan of saving data in cookies, and cookie support made up a big part of the code which just didn't make sense for me to bother adapting.\
Hence, I likely will not be implementing support for storing PASETO tokens in cookies unless there is a considerable amount of people wanting it.\
However, I will gladly accept PRs implementing tokens in cookies if someone else wants to implement it.

## License
This project is licensed under the terms of the MIT license.
