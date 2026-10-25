"""Synthetic secret generation. Standard library only: scripts/plant_guest.py loads this file by path on a
guest that has no scipy and no `vsec` package."""
import base64

_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


# synthetic test value, not a credential
def make_secret(kind, rng):
    if kind == "ssh_key":
        body = base64.b64encode(rng.randbytes(120)).decode()
        return f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body}\n-----END OPENSSH PRIVATE KEY-----"
    if kind == "aws":
        return "".join(rng.choice(_ALPHABET + "/+") for _ in range(40))
    if kind == "jwt":
        part = lambda n: base64.urlsafe_b64encode(rng.randbytes(n)).decode().rstrip("=")  # noqa: E731
        return f"eyJ{part(20)}.eyJ{part(30)}.{part(32)}"
    return rng.randbytes(32).hex()


# synthetic test value, not a credential
def plant_text(kind, secret):
    return f"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_ACCESS_KEY={secret}\n" if kind == "aws" else secret
