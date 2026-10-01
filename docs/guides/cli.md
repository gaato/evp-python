# Command line

The `evp` command is for relying-party developers and operators, and for issuer operators
checking their own setup. It needs the `cli` extra. You can run it without installing anything
into your project:

```sh
uvx --from "evp[cli]" evp --help
```

## `evp discover`

Check a domain's issuer the way a relying party sees it: the DNS record, the metadata, the keys,
and whether they work under a profile.

```sh
evp discover gmail.com
evp discover alice@example.com --profile draft-hardt-02
evp discover example.com --doh            # resolve over DNS-over-HTTPS
```

## `evp inspect`

Decode a token offline. It shows the headers, the claims, how long ago each part was issued,
whether `sd_hash` matches and the holder key thumbprint. **Signatures are not verified.**

```sh
pbpaste | evp inspect
evp inspect "$TOKEN" --json
```

## `evp verify`

Run the full verification, as your server would:

```sh
evp verify "$TOKEN" --audience https://example.com --nonce "$NONCE" --email alice@example.com
```

## Output and exit status

Every command accepts `--json` for scripts.

| Status | Meaning |
|---|---|
| 0 | success |
| 1 | verification failed, or discovery found problems |
| 2 | usage error |
| 3 | the `cli` extra is not installed |

```{note}
Tokens contain email addresses. Treat them as personal data, and avoid pasting real users'
tokens into shared terminals or issue trackers.
```
