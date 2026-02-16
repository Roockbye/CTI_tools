"""
Collection Engine - Orchestrateur de tous les collecteurs.
Gère l'exécution parallèle, le stockage en DB et le logging.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from cti_sentinel.config import ConfigLoader
from cti_sentinel.collectors.base import BaseCollector
from cti_sentinel.collectors.rss_collector import create_rss_collectors
from cti_sentinel.collectors.api_collectors import create_api_collectors
from cti_sentinel.database.manager import DatabaseManager
from cti_sentinel.database.models import ArticleStatus

logger = logging.getLogger(__name__)


class CollectionEngine:
    """
    Moteur de collecte centralisé.
    Orchestre tous les collecteurs et stocke les résultats en DB.
    """

    def __init__(self, config: ConfigLoader = None, db: DatabaseManager = None):
        self.config = config or ConfigLoader()
        self.db = db or DatabaseManager(self.config)
        self.collectors: List[BaseCollector] = []
        self._initialize_collectors()

    def _initialize_collectors(self):
        """Initialise tous les collecteurs configurés."""
        self.collectors = []

        # Collecteurs RSS
        rss_collectors = create_rss_collectors(self.config)
        self.collectors.extend(rss_collectors)

        # Collecteurs API
        api_collectors = create_api_collectors(self.config)
        self.collectors.extend(api_collectors)

        logger.info(
            "📋 %d collecteurs initialisés (%d RSS, %d API)",
            len(self.collectors), len(rss_collectors), len(api_collectors)
        )

    async def collect_all(self, categories: List[str] = None) -> Dict[str, Any]:
        """
        Lance la collecte sur tous les collecteurs (ou ceux filtrés par catégorie).

        Args:
            categories: Filtrer par catégories ["vulnerabilities", "news", etc.]

        Returns:
            Statistiques de collecte globales.
        """
        collectors = self.collectors
        if categories:
            collectors = [c for c in collectors if c.category in categories]

        logger.info("🚀 Lancement de la collecte sur %d sources", len(collectors))
        start_time = datetime.now(timezone.utc)

        # Exécuter les collecteurs en parallèle (par groupes pour limiter la charge)
        batch_size = 5
        all_results = []

        for i in range(0, len(collectors), batch_size):
            batch = collectors[i:i + batch_size]
            batch_names = [c.name for c in batch]
            logger.info("📦 Batch %d: %s", i // batch_size + 1, ", ".join(batch_names))

            tasks = [collector.run() for collector in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for collector, result in zip(batch, results):
                if isinstance(result, Exception):
                    logger.error("❌ Erreur collecteur %s: %s", collector.name, str(result))
                    self._log_collection(
                        collector, status="error", error_message=str(result)
                    )
                elif isinstance(result, list):
                    all_results.extend(result)
                    self._log_collection(collector, items=result)

            # Pause entre les batchs pour ne pas saturer le réseau
            if i + batch_size < len(collectors):
                await asyncio.sleep(2)

        # Stocker les résultats en DB
        stored_count = self._store_results(all_results)

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        stats = {
            "total_collected": len(all_results),
            "total_stored": stored_count,
            "sources_count": len(collectors),
            "duration_seconds": elapsed,
            "timestamp": start_time.isoformat(),
        }

        logger.info(
            "✅ Collecte terminée en %.1fs: %d items collectés, %d stockés",
            elapsed, len(all_results), stored_count
        )

        return stats

    async def collect_source(self, source_name: str) -> Dict[str, Any]:
        """Lance la collecte pour une source spécifique."""
        collector = next(
            (c for c in self.collectors if c.name == source_name), None
        )
        if not collector:
            raise ValueError(f"Source inconnue: {source_name}")

        results = await collector.run()
        stored = self._store_results(results)

        return {
            "source": source_name,
            "collected": len(results),
            "stored": stored,
            "stats": collector.stats,
        }

    def _store_results(self, items: List[Dict[str, Any]]) -> int:
        """Stocke les items collectés dans la base de données."""
        stored = 0

        with self.db.get_session() as session:
            for item in items:
                try:
                    item_type = item.get("type", "article")

                    if item_type == "vulnerability":
                        self._store_vulnerability(session, item)
                    elif item_type == "threat_actor":
                        self._store_threat_actor(session, item)
                    elif item_type == "ttp":
                        self._store_ttp(session, item)
                    elif item_type == "malware" and item.get("malware_info"):
                        self._store_malware(session, item)

                    # Toujours créer un article pour la timeline
                    article = self.db.add_article(
                        session,
                        title=item.get("title", "Sans titre"),
                        content=item.get("content", ""),
                        url=item.get("url", ""),
                        source_name=item.get("source_name", "unknown"),
                        source_category=item.get("source_category", "unknown"),
                        author=item.get("author"),
                        published_at=item.get("published_at"),
                        status=ArticleStatus.NEW,
                        raw_data=item.get("raw_data"),
                    )

                    if article:
                        stored += 1

                        # Ajouter les tags
                        for tag_name in item.get("tags", []):
                            if tag_name and isinstance(tag_name, str):
                                tag = self.db.get_or_create_tag(session, tag_name)
                                if tag not in article.tags:
                                    article.tags.append(tag)

                        # Stocker les IOCs associés
                        for ioc_data in item.get("iocs", []):
                            if isinstance(ioc_data, dict) and ioc_data.get("value"):
                                ioc = self.db.add_ioc(
                                    session,
                                    ioc_type=ioc_data.get("type", "url"),
                                    value=ioc_data["value"],
                                    source=item.get("source_name"),
                                    context=item.get("title"),
                                )
                                if ioc and ioc not in article.iocs:
                                    article.iocs.append(ioc)

                except Exception as e:
                    logger.warning("Erreur stockage item: %s", str(e))

        return stored

    def _store_vulnerability(self, session, item: dict):
        """Stocke une vulnérabilité dans la DB."""
        cve_id = item.get("cve_id")
        if not cve_id:
            return

        severity_map = {
            "CRITIQUE": "CRITIQUE",
            "HAUTE": "HAUTE",
            "MOYENNE": "MOYENNE",
            "FAIBLE": "FAIBLE",
            "INFO": "INFO",
        }

        self.db.upsert_vulnerability(
            session,
            cve_id=cve_id,
            title=item.get("title"),
            description=item.get("content"),
            description_fr=item.get("description_fr"),
            severity=severity_map.get(item.get("severity")),
            cvss_v3_score=item.get("cvss_v3_score"),
            cvss_v3_vector=item.get("cvss_v3_vector"),
            cvss_v2_score=item.get("cvss_v2_score"),
            cwe_ids=item.get("cwe_ids"),
            references=item.get("references"),
            published_date=item.get("published_at"),
            source=item.get("source_name"),
        )

    def _store_threat_actor(self, session, item: dict):
        """Stocke un threat actor dans la DB."""
        ta_data = item.get("threat_actor", {})
        if not ta_data.get("name"):
            return

        self.db.upsert_threat_actor(
            session,
            name=ta_data["name"],
            aliases=ta_data.get("aliases"),
            description=ta_data.get("description"),
            mitre_id=ta_data.get("mitre_id"),
            external_references=ta_data.get("references"),
        )

    def _store_ttp(self, session, item: dict):
        """Stocke un TTP dans la DB."""
        from cti_sentinel.database.models import TTP

        ttp_data = item.get("ttp", {})
        mitre_id = ttp_data.get("mitre_id")
        if not mitre_id:
            return

        existing = session.query(TTP).filter_by(mitre_id=mitre_id).first()
        if not existing:
            ttp = TTP(
                mitre_id=mitre_id,
                name=ttp_data.get("name", ""),
                tactic=", ".join(ttp_data.get("tactics", [])),
                description=item.get("content"),
                platforms=ttp_data.get("platforms"),
                data_sources=ttp_data.get("data_sources"),
                detection=ttp_data.get("detection"),
            )
            session.add(ttp)

    def _store_malware(self, session, item: dict):
        """Stocke un malware dans la DB."""
        from cti_sentinel.database.models import Malware

        info = item.get("malware_info", {})
        name = info.get("name") or info.get("family")
        if not name:
            return

        existing = session.query(Malware).filter_by(name=name).first()
        if existing:
            if info.get("sha256") and not existing.sha256:
                existing.sha256 = info["sha256"]
            return

        malware = Malware(
            name=name,
            family=info.get("family"),
            type=info.get("type"),
            description=item.get("content"),
            md5=info.get("md5"),
            sha1=info.get("sha1"),
            sha256=info.get("sha256"),
            ssdeep=info.get("ssdeep"),
            file_type=info.get("file_type"),
            file_size=info.get("file_size"),
            platforms=info.get("platforms"),
            mitre_id=info.get("mitre_id"),
            malpedia_url=info.get("malpedia_url"),
            aliases=info.get("aliases"),
        )
        session.add(malware)

    def _log_collection(self, collector: BaseCollector, status: str = "success",
                        items: list = None, error_message: str = None):
        """Enregistre un log de collecte en DB."""
        try:
            with self.db.get_session() as session:
                duration = None
                if collector.stats.get("start_time") and collector.stats.get("end_time"):
                    duration = (
                        collector.stats["end_time"] - collector.stats["start_time"]
                    ).total_seconds()

                self.db.log_collection(
                    session,
                    source_name=collector.name,
                    source_category=collector.category,
                    status=status,
                    items_collected=collector.stats.get("collected", 0),
                    items_new=collector.stats.get("new", 0),
                    items_duplicate=collector.stats.get("duplicates", 0),
                    items_error=collector.stats.get("errors", 0),
                    error_message=error_message,
                    duration_seconds=duration,
                )
        except Exception as e:
            logger.warning("Erreur log collecte: %s", str(e))

    def list_sources(self) -> List[Dict[str, str]]:
        """Liste toutes les sources configurées."""
        return [
            {
                "name": c.name,
                "category": c.category,
                "type": c.__class__.__name__,
            }
            for c in self.collectors
        ]
