"""
RSS/Atom Collector - Collecteur de flux RSS et Atom.
Supporte tous les blogs et sources d'actualités cyber.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from xml.etree import ElementTree as ET

import feedparser
from dateutil import parser as dateparser

from cti_sentinel.collectors.base import BaseCollector
from cti_sentinel.config import ConfigLoader

logger = logging.getLogger(__name__)


class RSSCollector(BaseCollector):
    """
    Collecteur générique de flux RSS/Atom.

    Supporte :
    - RSS 2.0
    - Atom 1.0
    - RSS 1.0 (RDF)
    - Parsing robuste avec feedparser
    """

    def __init__(
        self,
        name: str,
        category: str,
        urls: List[str],
        config: ConfigLoader = None,
        **kwargs,
    ):
        super().__init__(
            name=name,
            category=category,
            config=config,
            rate_limit=kwargs.get("rate_limit", 10),
            **{k: v for k, v in kwargs.items() if k != "rate_limit"},
        )
        self.urls = urls if isinstance(urls, list) else [urls]

    async def collect(self) -> List[Dict[str, Any]]:
        """Collecte les articles depuis tous les flux RSS configurés."""
        all_items = []

        for url in self.urls:
            try:
                # Cache activé (TTL défini dans config) pour éviter de
                # marteler les serveurs RSS lors de collectes fréquentes
                raw_content = await self.fetch(url, use_cache=True)
                if raw_content is None:
                    self.logger.warning("Pas de contenu pour %s", url[:80])
                    continue

                # Parser le flux
                if isinstance(raw_content, str):
                    feed = feedparser.parse(raw_content)
                else:
                    self.logger.warning("Format inattendu pour %s", url[:80])
                    continue

                if feed.bozo and not feed.entries:
                    self.logger.warning(
                        "Erreur de parsing RSS pour %s: %s",
                        url[:80], feed.bozo_exception
                    )
                    continue

                self.logger.info(
                    "📰 %s : %d entrées trouvées dans %s",
                    self.name, len(feed.entries), url[:80]
                )

                for entry in feed.entries:
                    try:
                        item = self._parse_entry(entry, url)
                        if item:
                            all_items.append(item)
                    except Exception as e:
                        self.logger.warning(
                            "Erreur parsing entrée RSS: %s", str(e)
                        )
                        self.stats["errors"] += 1

            except Exception as e:
                self.logger.error("Erreur collecte RSS %s: %s", url[:80], str(e))
                self.stats["errors"] += 1

        self.stats["new"] = len(all_items)
        return all_items

    def _parse_entry(self, entry: Any, feed_url: str) -> Optional[Dict[str, Any]]:
        """Parse une entrée RSS/Atom en format normalisé."""
        title = entry.get("title", "").strip()
        if not title:
            return None

        # Extraire le contenu
        content = ""
        if hasattr(entry, "content") and entry.content:
            content = entry.content[0].get("value", "")
        elif hasattr(entry, "summary"):
            content = entry.get("summary", "")
        elif hasattr(entry, "description"):
            content = entry.get("description", "")

        # Nettoyer le contenu HTML basique
        content = self._clean_html(content)

        # URL de l'article
        url = entry.get("link", entry.get("id", feed_url))

        # Date de publication
        published_at = None
        for date_field in ["published_parsed", "updated_parsed", "created_parsed"]:
            parsed_date = entry.get(date_field)
            if parsed_date:
                try:
                    published_at = datetime(*parsed_date[:6], tzinfo=timezone.utc)
                    break
                except (ValueError, TypeError):
                    pass

        if published_at is None:
            for date_field in ["published", "updated", "created"]:
                date_str = entry.get(date_field)
                if date_str:
                    try:
                        published_at = dateparser.parse(date_str)
                        if published_at and published_at.tzinfo is None:
                            published_at = published_at.replace(tzinfo=timezone.utc)
                        break
                    except (ValueError, TypeError):
                        pass

        # Auteur
        author = entry.get("author", entry.get("dc_creator"))

        # Tags/catégories
        tags = []
        if hasattr(entry, "tags"):
            tags = [tag.get("term", "") for tag in entry.get("tags", []) if tag.get("term")]

        return self.normalize_item({
            "title": title,
            "content": content,
            "url": url,
            "author": author,
            "published_at": published_at,
            "tags": tags,
            "feed_url": feed_url,
        })

    @staticmethod
    def _clean_html(html_text: str) -> str:
        """Nettoyage basique du HTML vers texte brut."""
        if not html_text:
            return ""

        import re
        # Supprimer les balises script et style
        text = re.sub(r'<script[^>]*>.*?</script>', '', html_text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        # Remplacer <br>, <p>, <div> par des sauts de ligne
        text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
        text = re.sub(r'</(p|div|h[1-6]|li)>', '\n', text, flags=re.IGNORECASE)
        # Supprimer toutes les autres balises
        text = re.sub(r'<[^>]+>', '', text)
        # Nettoyer les entités HTML communes
        text = text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
        text = text.replace('&quot;', '"').replace('&#39;', "'").replace('&nbsp;', ' ')
        # Normaliser les espaces
        text = re.sub(r'\n{3,}', '\n\n', text)
        text = re.sub(r' {2,}', ' ', text)
        return text.strip()


# ============================================================================
# INSTANCES PRÉ-CONFIGURÉES POUR CHAQUE SOURCE RSS
# ============================================================================

def create_rss_collectors(config: ConfigLoader = None) -> List[RSSCollector]:
    """Crée tous les collecteurs RSS activés dans la configuration."""
    cfg = config or ConfigLoader()
    collectors = []

    # Parcourir toutes les sources RSS
    rss_sources = {
        "vulnerabilities": {
            "cert_fr": {"category": "vulnerabilities"},
            "exploit_db": {"category": "vulnerabilities"},
        },
        "news": {
            "bleeping_computer": {"category": "news"},
            "the_hacker_news": {"category": "news"},
            "krebs_on_security": {"category": "news"},
            "dark_reading": {"category": "news"},
            "schneier": {"category": "news"},
        },
        "geopolitics": {
            "cyberscoop": {"category": "geopolitics"},
            "the_record": {"category": "geopolitics"},
            "security_affairs": {"category": "geopolitics"},
        },
        "reports": {
            "mandiant": {"category": "reports"},
            "crowdstrike": {"category": "reports"},
            "sentinel_one": {"category": "reports"},
            "talos": {"category": "reports"},
        },
    }

    for section, sources in rss_sources.items():
        for source_name, meta in sources.items():
            source_cfg = cfg.get_source_config(section, source_name)
            if source_cfg and source_cfg.get("enabled", False) and source_cfg.get("type") == "rss":
                urls = source_cfg.get("urls", [])
                if urls:
                    collector = RSSCollector(
                        name=source_name,
                        category=meta["category"],
                        urls=urls,
                        config=cfg,
                        rate_limit=source_cfg.get("rate_limit", 10),
                    )
                    collectors.append(collector)
                    logger.info("✅ Collecteur RSS configuré: %s (%d URLs)", source_name, len(urls))

    return collectors
