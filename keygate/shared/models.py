"""
KeyGate - Shared models and crypto utilities
Author: Víctor Martín Sotoca
License: Apache 2.0
"""

import os
import json
import hashlib
import secrets
import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

# ── Permission flags ────────────────────────────────────────────────────────
class Perm:
    READ  = "read"
    WRITE = "write"
    ADMIN = "admin"

    ALL = [READ, WRITE, ADMIN]

    @staticmethod
    def validate(perms: list[str]) -> bool:
        return all(p in Perm.ALL for p in perms)


# ── Token dataclass ─────────────────────────────────────────────────────────
@dataclass
class Token:
    token_id:    str
    name:        str
    perms:       list[str]
    created_at:  str
    expires_at:  Optional[str]
    last_used:   Optional[str]
    revoked:     bool
    note:        str
    token_hash:  str           # SHA-256 of the raw token (never store raw)

    @staticmethod
    def generate(name: str, perms: list[str], expires_days: Optional[int] = None, note: str = "") -> tuple["Token", str]:
        """Returns (Token, raw_token_string). Store raw only on creation."""
        raw = "kg_" + secrets.token_urlsafe(40)
        token_hash = hashlib.sha256(raw.encode()).hexdigest()
        token_id   = secrets.token_hex(8)
        now        = datetime.datetime.utcnow().isoformat()
        expires_at = None
        if expires_days:
            exp = datetime.datetime.utcnow() + datetime.timedelta(days=expires_days)
            expires_at = exp.isoformat()

        tok = Token(
            token_id   = token_id,
            name       = name,
            perms      = perms,
            created_at = now,
            expires_at = expires_at,
            last_used  = None,
            revoked    = False,
            note       = note,
            token_hash = token_hash,
        )
        return tok, raw

    def is_valid(self) -> tuple[bool, str]:
        if self.revoked:
            return False, "Token revocado"
        if self.expires_at:
            exp = datetime.datetime.fromisoformat(self.expires_at)
            if datetime.datetime.utcnow() > exp:
                return False, "Token expirado"
        return True, "OK"

    def has_perm(self, perm: str) -> bool:
        return perm in self.perms or Perm.ADMIN in self.perms

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Token":
        return Token(**d)


# ── Token store (JSON file) ─────────────────────────────────────────────────
class TokenStore:
    def __init__(self, path: str):
        self.path = path
        self._tokens: dict[str, Token] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path) as f:
                raw = json.load(f)
            self._tokens = {k: Token.from_dict(v) for k, v in raw.items()}

    def _save(self):
        with open(self.path, "w") as f:
            json.dump({k: v.to_dict() for k, v in self._tokens.items()}, f, indent=2)

    def add(self, token: Token):
        self._tokens[token.token_id] = token
        self._save()

    def get_by_raw(self, raw: str) -> Optional[Token]:
        h = hashlib.sha256(raw.encode()).hexdigest()
        for tok in self._tokens.values():
            if tok.token_hash == h:
                return tok
        return None

    def get_by_id(self, token_id: str) -> Optional[Token]:
        return self._tokens.get(token_id)

    def revoke(self, token_id: str) -> bool:
        if token_id in self._tokens:
            self._tokens[token_id].revoked = True
            self._save()
            return True
        return False

    def touch(self, token_id: str):
        if token_id in self._tokens:
            self._tokens[token_id].last_used = datetime.datetime.utcnow().isoformat()
            self._save()

    def all(self) -> list[Token]:
        return list(self._tokens.values())
