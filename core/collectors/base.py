"""
Collector base class and registry.

Every source implements collect() and returns Signals. Collectors declare
whether they need an API key so the CLI can tell you what will actually run
before you wait on it.
"""

import asyncio
import os
from abc import ABC, abstractmethod
from typing import Dict, List, Optional

import httpx

from ..signals import Signal

USER_AGENT = "IndiaThreatLandscape/2.0 (defensive threat research)"

_REGISTRY: Dict[str, type] = {}


def register(cls):
    _REGISTRY[cls.name] = cls
    return cls


def all_collectors() -> Dict[str, type]:
    return dict(_REGISTRY)


def available_collectors() -> Dict[str, Dict]:
    """Which collectors can run right now, and what each is missing."""
    out = {}
    for name, cls in _REGISTRY.items():
        missing = [k for k in cls.required_env if not os.getenv(k, "").strip()]
        out[name] = {
            "class": cls,
            "description": cls.description,
            "signal_types": cls.signal_types,
            "required_env": cls.required_env,
            "missing_env": missing,
            "ready": not missing,
            "free": cls.free,
        }
    return out


class BaseCollector(ABC):
    name: str = "base"
    description: str = ""
    signal_types: List[str] = []
    required_env: List[str] = []
    free: bool = True
    timeout: int = 30

    def __init__(self, **options):
        self.options = options
        self.errors: List[str] = []

    # -- helpers ----------------------------------------------------------

    def env(self, key: str, default: str = "") -> str:
        return os.getenv(key, default).strip()

    async def get_json(self, client: httpx.AsyncClient, url: str,
                       headers: Optional[Dict] = None,
                       params: Optional[Dict] = None):
        try:
            resp = await client.get(url, headers=headers, params=params,
                                    timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            self.errors.append(f"{url} returned HTTP {resp.status_code}")
        except Exception as exc:
            self.errors.append(f"{url}: {type(exc).__name__}: {exc}")
        return None

    async def get_text(self, client: httpx.AsyncClient, url: str,
                       headers: Optional[Dict] = None) -> Optional[str]:
        try:
            resp = await client.get(url, headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                return resp.text
            self.errors.append(f"{url} returned HTTP {resp.status_code}")
        except Exception as exc:
            self.errors.append(f"{url}: {type(exc).__name__}: {exc}")
        return None

    async def post_json(self, client: httpx.AsyncClient, url: str,
                        data=None, json_body=None,
                        headers: Optional[Dict] = None):
        try:
            resp = await client.post(url, data=data, json=json_body,
                                     headers=headers, timeout=self.timeout)
            if resp.status_code == 200:
                return resp.json()
            self.errors.append(f"{url} returned HTTP {resp.status_code}")
        except Exception as exc:
            self.errors.append(f"{url}: {type(exc).__name__}: {exc}")
        return None

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(headers={"User-Agent": USER_AGENT},
                                 follow_redirects=True)

    # -- contract ---------------------------------------------------------

    @abstractmethod
    async def collect(self) -> List[Signal]:
        ...

    def run(self) -> List[Signal]:
        return asyncio.run(self.collect())
