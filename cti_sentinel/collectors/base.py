"""
Base Collector - Classe abstraite pour tous les collecteurs.
Gestion commune du rate limiting, retry, cache et logging.
"""

import asyncio
import hashlib
import json
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiohttp
from aiohttp import ClientTimeout

from cti_sentinel.config import ConfigLoader

logger = logging.getLogger(__name__)


class RateLimiter:
    """Rate limiter simple basé sur un token bucket."""

    def __init__(self, requests_per_period: int, period_seconds: int = 60):
        self.max_tokens = requests_per_period
        self.period = period_seconds
        self.tokens = requests_per_period
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self):
        """Attend jusqu'à ce qu'un token soit disponible."""
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            self.tokens = min(
                self.max_tokens,
                self.tokens + (elapsed / self.period) * self.max_tokens
            )
            self.last_refill = now

            if self.tokens < 1:
                wait_time = (1 - self.tokens) / (self.max_tokens / self.period)
                logger.debug("Rate limit: attente de %.1fs", wait_time)
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class CacheManager:
    """Cache fichier simple pour les réponses HTTP."""

    def __init__(self, cache_dir: str = "./cache", ttl: int = 3600):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = ttl

    def _key_path(self, key: str) -> Path:
        hash_key = hashlib.md5(key.encode()).hexdigest()
        return self.cache_dir / f"{hash_key}.json"

    def get(self, key: str) -> Optional[Any]:
        """Récupère une valeur du cache si encore valide."""
        path = self._key_path(key)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if time.time() - data.get("timestamp", 0) > self.ttl:
                path.unlink(missing_ok=True)
                return None
            return data.get("value")
        except (json.JSONDecodeError, OSError):
            return None

    def set(self, key: str, value: Any):
        """Stocke une valeur dans le cache."""
        path = self._key_path(key)
        try:
            data = {"timestamp": time.time(), "value": value}
            path.write_text(json.dumps(data, ensure_ascii=False, default=str), encoding="utf-8")
        except OSError as e:
            logger.warning("Erreur écriture cache: %s", e)

    def clear(self):
        """Vide le cache."""
        for f in self.cache_dir.glob("*.json"):
            f.unlink(missing_ok=True)


class BaseCollector(ABC):
    """
    Classe de base pour tous les collecteurs de données CTI.

    Fournit :
    - Client HTTP async avec retry et timeout
    - Rate limiting par source
    - Cache des réponses
    - Logging structuré
    - Gestion des erreurs standardisée
    """

    def __init__(
        self,
        name: str,
        category: str,
        config: ConfigLoader = None,
        rate_limit: int = 10,
        retry_count: int = 3,
        retry_delay: float = 2.0,
        timeout: int = 30,
    ):
        self.name = name
        self.category = category
        self.config = config or ConfigLoader()
        self.rate_limiter = RateLimiter(rate_limit, period_seconds=60)
        self.retry_count = retry_count
        self.retry_delay = retry_delay
        self.timeout = ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None

        # Cache
        project_root = Path(__file__).parent.parent.parent
        cache_dir = project_root / self.config.get("general.cache_dir", "./cache")
        cache_ttl = self.config.get("cache.ttl", 3600)
        self.cache = CacheManager(str(cache_dir / self.name), ttl=cache_ttl)

        # Stats de collecte
        self.stats = {
            "collected": 0,
            "new": 0,
            "duplicates": 0,
            "errors": 0,
            "start_time": None,
            "end_time": None,
        }

        self.logger = logging.getLogger(f"collector.{name}")

    async def _get_session(self) -> aiohttp.ClientSession:
        """Retourne ou crée une session HTTP."""
        if self._session is None or self._session.closed:
            # User-Agent légitime pour éviter les blocages WAF/Cloudflare.
            # Ce header identifie un navigateur courant, ce qui est la norme
            # pour les outils de veille consommant des flux RSS publics.
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) "
                    "Gecko/20100101 Firefox/124.0"
                ),
                "Accept": "application/json, application/xml, text/xml, */*",
                "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
            }
            self._session = aiohttp.ClientSession(
                timeout=self.timeout,
                headers=headers,
                # ssl=True (défaut) — NE PAS désactiver la vérification SSL
                # limit_per_host=3 évite de saturer un même serveur
                connector=aiohttp.TCPConnector(
                    limit=10,
                    limit_per_host=3,
                    ssl=True,
                ),
            )
        return self._session

    async def close(self):
        """Ferme la session HTTP."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        headers: dict = None,
        params: dict = None,
        json_data: dict = None,
        use_cache: bool = True,
    ) -> Optional[Any]:
        """
        Effectue une requête HTTP avec rate limiting, retry et cache.

        Returns:
            Contenu de la réponse (str ou dict) ou None en cas d'erreur.
        """
        cache_key = f"{method}:{url}:{json.dumps(params or {}, sort_keys=True)}"

        # Vérifier le cache
        if use_cache and method == "GET":
            cached = self.cache.get(cache_key)
            if cached is not None:
                self.logger.debug("Cache hit: %s", url[:80])
                return cached

        # Rate limiting
        await self.rate_limiter.acquire()

        session = await self._get_session()

        for attempt in range(1, self.retry_count + 1):
            try:
                kwargs = {"headers": headers or {}}
                if params:
                    kwargs["params"] = params
                if json_data:
                    kwargs["json"] = json_data

                async with session.request(method, url, **kwargs) as response:
                    if response.status == 200:
                        content_type = response.headers.get("Content-Type", "")

                        if "json" in content_type:
                            data = await response.json()
                        elif "xml" in content_type or url.endswith((".xml", ".rss", ".atom", "/feed")):
                            data = await response.text()
                        else:
                            data = await response.text()

                        # Mettre en cache
                        if use_cache and method == "GET":
                            self.cache.set(cache_key, data)

                        return data

                    elif response.status == 429:
                        # Rate limited — respecter strictement le header Retry-After
                        retry_after_raw = response.headers.get("Retry-After", "60")
                        try:
                            retry_after = min(int(retry_after_raw), 300)  # Max 5 min
                        except ValueError:
                            retry_after = 60
                        self.logger.warning(
                            "⏳ Rate limited sur %s, attente %ds (Retry-After respecté)",
                            url[:80], retry_after,
                        )
                        await asyncio.sleep(retry_after)
                        continue

                    elif response.status in (401, 403):
                        self.logger.error(
                            "Accès refusé (%d) pour %s", response.status, url[:80]
                        )
                        return None

                    elif response.status >= 500:
                        self.logger.warning(
                            "Erreur serveur (%d) sur %s, tentative %d/%d",
                            response.status, url[:80], attempt, self.retry_count
                        )
                        await asyncio.sleep(self.retry_delay * attempt)
                        continue
                    else:
                        self.logger.warning(
                            "Réponse inattendue (%d) de %s", response.status, url[:80]
                        )
                        return None

            except asyncio.TimeoutError:
                self.logger.warning(
                    "Timeout sur %s, tentative %d/%d", url[:80], attempt, self.retry_count
                )
                await asyncio.sleep(self.retry_delay * attempt)
            except aiohttp.ClientError as e:
                self.logger.warning(
                    "Erreur réseau sur %s: %s, tentative %d/%d",
                    url[:80], str(e), attempt, self.retry_count
                )
                await asyncio.sleep(self.retry_delay * attempt)
            except Exception as e:
                self.logger.error("Erreur inattendue sur %s: %s", url[:80], str(e))
                self.stats["errors"] += 1
                return None

        self.logger.error("Échec après %d tentatives pour %s", self.retry_count, url[:80])
        self.stats["errors"] += 1
        return None

    @abstractmethod
    async def collect(self) -> List[Dict[str, Any]]:
        """
        Méthode principale de collecte. À implémenter par chaque sous-classe.

        Returns:
            Liste de dictionnaires normalisés prêts pour insertion en DB.
        """
        raise NotImplementedError

    async def run(self) -> List[Dict[str, Any]]:
        """Exécute la collecte avec tracking des stats."""
        self.stats["start_time"] = datetime.now(timezone.utc)
        self.logger.info("🔄 Début de collecte: %s (%s)", self.name, self.category)

        try:
            items = await self.collect()
            self.stats["collected"] = len(items)
            self.logger.info(
                "✅ Collecte terminée: %s - %d items collectés "
                "(%d nouveaux, %d doublons, %d erreurs)",
                self.name, self.stats["collected"], self.stats["new"],
                self.stats["duplicates"], self.stats["errors"]
            )
            return items
        except Exception as e:
            self.logger.error("❌ Erreur collecte %s: %s", self.name, str(e), exc_info=True)
            self.stats["errors"] += 1
            return []
        finally:
            self.stats["end_time"] = datetime.now(timezone.utc)
            await self.close()

    @staticmethod
    def _make_json_safe(obj: Any) -> Any:
        """Convertit récursivement les objets non-JSON-sérialisables (datetime, etc.)."""
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, dict):
            return {k: BaseCollector._make_json_safe(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [BaseCollector._make_json_safe(v) for v in obj]
        return obj

    def normalize_item(self, raw_data: dict) -> Dict[str, Any]:
        """
        Normalise un item brut dans le format standard.

        Format standard :
        {
            "title": str,
            "content": str,
            "url": str,
            "source_name": str,
            "source_category": str,
            "author": str | None,
            "published_at": datetime | None,
            "raw_data": dict,
        }
        """
        return {
            "title": raw_data.get("title", "Sans titre"),
            "content": raw_data.get("content", raw_data.get("description", "")),
            "url": raw_data.get("url", raw_data.get("link", "")),
            "source_name": self.name,
            "source_category": self.category,
            "author": raw_data.get("author"),
            "published_at": raw_data.get("published_at"),
            "raw_data": self._make_json_safe(raw_data),
        }
