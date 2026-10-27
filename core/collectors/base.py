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

    # Transient failures worth retrying: rate limits and server-side errors
    RETRY_STATUS = {429, 500, 502, 503, 504}
    max_attempts: int = 3
    backoff_seconds: float = 2.0

    async def _request(self, client: httpx.AsyncClient, method: str, url: str,
                       **kwargs) -> Optional[httpx.Response]:
        """One HTTP request with retries and exponential backoff.

        Retries network errors, 429 and 5xx (honouring Retry-After up to 60s);
        other 4xx answers are final. Every failed attempt is kept in
        self.errors so source-health reporting can see flaky feeds.
        """
        for attempt in range(1, self.max_attempts + 1):
            wait = self.backoff_seconds * (2 ** (attempt - 1))
            try:
                resp = await client.request(method, url, timeout=self.timeout, **kwargs)
            except Exception as exc:
                self.errors.append(f"{url}: {type(exc).__name__}: {exc} (attempt {attempt}/{self.max_attempts})")
            else:
                if resp.status_code == 200:
                    return resp
                self.errors.append(f"{url} returned HTTP {resp.status_code} (attempt {attempt}/{self.max_attempts})")
                if resp.status_code not in self.RETRY_STATUS:
                    return None
                retry_after = resp.headers.get("Retry-After", "")
                if retry_after.isdigit():
                    wait = min(float(retry_after), 60.0)
            if attempt < self.max_attempts:
                await asyncio.sleep(wait)
        return None

    async def get_json(self, client: httpx.AsyncClient, url: str,
                       headers: Optional[Dict] = None,
                       params: Optional[Dict] = None):
        resp = await self._request(client, "GET", url, headers=headers, params=params)
        if resp is None:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            self.errors.append(f"{url}: response was not JSON ({exc})")
            return None

    async def get_text(self, client: httpx.AsyncClient, url: str,
                       headers: Optional[Dict] = None) -> Optional[str]:
        resp = await self._request(client, "GET", url, headers=headers)
        return resp.text if resp is not None else None

    async def post_json(self, client: httpx.AsyncClient, url: str,
                        data=None, json_body=None,
                        headers: Optional[Dict] = None):
        resp = await self._request(client, "POST", url, data=data, json=json_body, headers=headers)
        if resp is None:
            return None
        try:
            return resp.json()
        except ValueError as exc:
            self.errors.append(f"{url}: response was not JSON ({exc})")
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
