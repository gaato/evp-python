# API reference

## `evp`

Everything most applications need is importable from the top-level package.

```{eval-rst}
.. automodule:: evp
   :members:
   :imported-members:

.. data:: evp.DEFAULT_PROFILE
   :type: Profile

   The profile verifiers use unless told otherwise: ``compat-2026-10``.

.. data:: evp.profile.PROFILES
   :type: Mapping[str, Profile]

   All presets by name; see :meth:`Profile.named`.

.. autodata:: evp.Clock

.. autodata:: evp.Observer
```

## Verification core

```{eval-rst}
.. automodule:: evp.core
   :members: verification_steps, ResolveTxt, FetchJson, MarkUsed, Effect, Steps, replay_key

.. automodule:: evp.token
   :members: parse_token, ParsedToken, CompactJWT, compute_sd_hash, build_kb, sign_jwt

.. automodule:: evp.discovery
```

## Diagnostics

```{eval-rst}
.. automodule:: evp.diagnostics
```

## Adapters

```{eval-rst}
.. automodule:: evp.adapters.dnspython

.. automodule:: evp.adapters.httpx

.. automodule:: evp.adapters.doh
```

## Issuer (experimental)

```{eval-rst}
.. automodule:: evp.issuer
   :members:
   :imported-members:
```

## Testing

```{eval-rst}
.. automodule:: evp.testing
```
