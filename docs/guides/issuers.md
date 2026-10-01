# For issuer operators

If you run an email service and issue EVP tokens, you can check what relying parties using this
library will see.

```sh
uvx --from "evp[cli]" evp discover your-domain.example
uvx --from "evp[cli]" evp discover your-domain.example --profile draft-hardt-02 --json
```

`discover` reports problems such as:

- a missing `_email-verification` TXT record, or more than one `iss=` record;
- metadata whose `issuer` does not exactly match the delegated `https://<host>`;
- a `jwks_uri` that is not HTTPS;
- signing algorithms the profile does not accept;
- no key able to verify the advertised algorithms;
- keys without `kid` when the profile requires one.

The same checks are available in code, for example from a monitoring job:

```python
from evp.diagnostics import discover

report = discover("your-domain.example", resolver=..., fetcher=...)
assert report.ok, report.problems
```

To test token issuance end to end, combine your issuer with {class}`evp.testing.FakeBrowser`. It
holds a key-binding key and builds the presentation token from your EVT.
