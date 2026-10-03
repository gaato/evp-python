# Password recovery without the email

Password recovery usually emails a link with a reset token. Clicking it proves that the user
controls the address. A valid EVP token proves the same, so the server can hand over the reset
token at once and skip the email. Nothing new is trusted: it is the token the email would have
carried.

From [`examples/fastapi_spa`](https://github.com/gaato/pyevp/tree/main/examples/fastapi_spa), a
JSON API that keeps the nonce in a cookie (see {doc}`spa`):

```{literalinclude} ../../examples/fastapi_spa/app.py
:language: python
:start-after: "# recovery:start"
:end-before: "# recovery:end"
```

- Verify the token before looking the user up. The reply, its cookies and its timing then do not
  depend on whether the address is registered. Only when the token proves the address does the
  reply differ, and then only the owner of the address learns that it is registered.
- Send the fallback email in the background, so that its delay does not give the answer away
  either.
- Hand the reset token only to active users, as the email flow would.
- Keep the reset token out of URLs in the frontend. Pass it to the next screen in memory or in
  router state, not in a query string, which ends up in the browser history and in `Referer`
  headers.
- EVP replaces the email, not other factors: if the account has a second factor, the reset should
  still ask for it.
