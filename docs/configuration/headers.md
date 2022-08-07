These are only applicable if `authpaseto_token_location` is use headers.

`authpaseto_header_name`
:   What header to look for the PASETO in a request. Defaults to `Authorization`

`authpaseto_header_type`
:   What type of header the PASETO is in. Defaults to `Bearer`. This can be an empty string,
    in which case the header contains only the PASETO instead like `HeaderName: Bearer <PASETO>`
