These are only applicable if `authpaseto_token_location` is use headers.

`authpaseto_header_name`
:   What header to look for the JWT in a request. Defaults to `Authorization`

`authpaseto_header_type`
:   What type of header the JWT is in. Defaults to `Bearer`. This can be an empty string,
    in which case the header contains only the JWT instead like `HeaderName: Bearer <JWT>`
