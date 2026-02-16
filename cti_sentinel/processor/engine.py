"""
Processing Engine - Orchestrateur du traitement intelligent des articles.
Combine extraction regex, analyse LLM, enrichissement et déduplication.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

from cti_sentinel.config import ConfigLoader
from cti_sentinel.database.manager import DatabaseManager
from cti_sentinel.database.models import Article, ArticleStatus, SeverityLevel, Flashcard
from cti_sentinel.processor.llm_client import (
    OllamaClient, CTI_SYSTEM_PROMPT,
    SEVERITY_SCORING_PROMPT, IOC_EXTRACTION_PROMPT,
    SUMMARY_PROMPT, TTP_IDENTIFICATION_PROMPT,
    FLASHCARD_GENERATION_PROMPT, YARA_SIGMA_PROMPT,
)
from cti_sentinel.processor.ioc_extractor import IOCExtractor

logger = logging.getLogger(__name__)


class ProcessingEngine:
    """
    Moteur de traitement des articles collectés.

    Pipeline:
    1. Extraction IOCs par regex (rapide)
    2. Scoring de sévérité (LLM)
    3. Résumé en français (LLM)
    4. Extraction IOCs avancée (LLM)
    5. Identification TTPs (LLM)
    6. Enrichissement CVE (API)
    7. Génération flashcards (LLM, optionnel)
    """

    def __init__(self, config: ConfigLoader = None, db: DatabaseManager = None):
        self.config = config or ConfigLoader()
        self.db = db or DatabaseManager(self.config)
        self.llm = OllamaClient(self.config)
        self.ioc_extractor = IOCExtractor()
        self.batch_size = self.config.get("llm.batch_size", 10)

    async def process_pending_articles(self, limit: int = 100) -> Dict[str, int]:
        """Traite tous les articles en attente."""
        stats = {"processed": 0, "errors": 0, "skipped": 0}

        # Vérifier la disponibilité du LLM
        llm_available = await self.llm.is_available()
        if not llm_available:
            logger.warning("⚠️ LLM non disponible, traitement limité (regex uniquement)")

        with self.db.get_session() as session:
            articles = (
                session.query(Article)
                .filter(Article.status == ArticleStatus.NEW)
                .order_by(Article.collected_at.desc())
                .limit(limit)
                .all()
            )

            if not articles:
                logger.info("Aucun article en attente de traitement")
                return stats

            logger.info("🔄 %d articles à traiter", len(articles))

            # Traitement par batch
            for i in range(0, len(articles), self.batch_size):
                batch = articles[i:i + self.batch_size]
                batch_num = i // self.batch_size + 1
                total_batches = (len(articles) + self.batch_size - 1) // self.batch_size
                logger.info("📦 Batch %d/%d (%d articles)", batch_num, total_batches, len(batch))

                for article in batch:
                    try:
                        article.status = ArticleStatus.PROCESSING
                        session.flush()

                        await self._process_single_article(session, article, llm_available)

                        article.status = ArticleStatus.PROCESSED
                        article.processed_at = datetime.now(timezone.utc)
                        stats["processed"] += 1

                    except Exception as e:
                        logger.error(
                            "Erreur traitement article '%s': %s",
                            article.title[:50], str(e), exc_info=True
                        )
                        article.status = ArticleStatus.ERROR
                        stats["errors"] += 1

                session.commit()

        await self.llm.close()

        logger.info(
            "✅ Traitement terminé: %d traités, %d erreurs, %d ignorés",
            stats["processed"], stats["errors"], stats["skipped"]
        )
        return stats

    async def _process_single_article(
        self, session, article: Article, llm_available: bool
    ):
        """Traite un article individuel avec le pipeline complet."""
        content = article.content or ""
        title = article.title or ""

        # ── Étape 1: Extraction IOCs par regex (toujours) ─────────────────
        regex_iocs = self.ioc_extractor.extract(f"{title}\n{content}")
        for ioc_data in regex_iocs:
            ioc = self.db.add_ioc(
                session,
                ioc_type=ioc_data.type,
                value=ioc_data.value,
                context=ioc_data.context,
                confidence=ioc_data.confidence,
                source=article.source_name,
            )
            if ioc and ioc not in article.iocs:
                article.iocs.append(ioc)

        # Extraire les CVE
        cve_ids = self.ioc_extractor.extract_cves(f"{title}\n{content}")
        for cve_id in cve_ids:
            vuln = self.db.upsert_vulnerability(
                session, cve_id=cve_id.upper(), source=article.source_name
            )
            if vuln and vuln not in article.vulnerabilities:
                article.vulnerabilities.append(vuln)

        if not llm_available:
            # Sans LLM, scoring basique par mots-clés
            article.severity = self._basic_severity_scoring(title, content)
            return

        # ── Étape 2: Scoring de sévérité (LLM) ───────────────────────────
        severity_result = await self.llm.generate_json(
            prompt=SEVERITY_SCORING_PROMPT.format(
                title=title, source=article.source_name,
                content=content[:3000],
            ),
            system=CTI_SYSTEM_PROMPT,
        )
        if severity_result:
            severity_str = severity_result.get("severity", "INFO")
            try:
                article.severity = SeverityLevel(severity_str)
            except ValueError:
                article.severity = SeverityLevel.INFO

            article.categories = severity_result.get("categories", [])

            # Ajouter les tags de catégories
            for cat in severity_result.get("categories", []):
                tag = self.db.get_or_create_tag(session, cat, category="type")
                if tag not in article.tags:
                    article.tags.append(tag)

            for sector in severity_result.get("impact_sectors", []):
                tag = self.db.get_or_create_tag(session, sector, category="sector")
                if tag not in article.tags:
                    article.tags.append(tag)

        # ── Étape 3: Résumé en français (LLM) ────────────────────────────
        summary_result = await self.llm.generate_json(
            prompt=SUMMARY_PROMPT.format(
                title=title, source=article.source_name,
                date=str(article.published_at or ""),
                content=content[:4000],
            ),
            system=CTI_SYSTEM_PROMPT,
        )
        if summary_result:
            article.summary_fr = summary_result.get("summary_fr", "")
            article.summary = article.summary_fr

        # ── Étape 4: Extraction IOCs avancée (LLM) ───────────────────────
        if len(content) > 200:  # Seulement pour articles substantiels
            ioc_result = await self.llm.generate_json(
                prompt=IOC_EXTRACTION_PROMPT.format(
                    title=title, content=content[:4000],
                ),
                system=CTI_SYSTEM_PROMPT,
            )
            if ioc_result:
                # Ajouter les IOCs du LLM — UNIQUEMENT si présents dans le texte source.
                # Les LLM peuvent halluciner des IOCs ; on vérifie que la valeur
                # apparaît réellement dans le contenu original de l'article.
                source_text = f"{title}\n{content}".lower()
                for ioc_data in ioc_result.get("iocs", []):
                    ioc_value = ioc_data.get("value", "")
                    if ioc_value and ioc_value.lower() in source_text:
                        ioc = self.db.add_ioc(
                            session,
                            ioc_type=ioc_data.get("type", "url"),
                            value=ioc_value,
                            context=ioc_data.get("context", ""),
                            source=f"{article.source_name}_llm",
                        )
                        if ioc and ioc not in article.iocs:
                            article.iocs.append(ioc)
                    elif ioc_value:
                        logger.debug(
                            "IOC LLM ignoré (non trouvé dans le texte source): %s",
                            ioc_value[:60],
                        )

                # Threat actors
                for ta_name in ioc_result.get("threat_actors", []):
                    if ta_name:
                        ta = self.db.upsert_threat_actor(session, name=ta_name)
                        if ta not in article.threat_actors:
                            article.threat_actors.append(ta)

                # CVEs supplémentaires
                for cve_id in ioc_result.get("cves", []):
                    vuln = self.db.upsert_vulnerability(
                        session, cve_id=cve_id.upper(), source=article.source_name
                    )
                    if vuln and vuln not in article.vulnerabilities:
                        article.vulnerabilities.append(vuln)

        # ── Étape 5: Identification TTPs (LLM) ───────────────────────────
        if article.severity in (SeverityLevel.CRITIQUE, SeverityLevel.HAUTE) or \
           article.source_category in ("reports", "apt_groups"):
            ttp_result = await self.llm.generate_json(
                prompt=TTP_IDENTIFICATION_PROMPT.format(
                    title=title, content=content[:4000],
                ),
                system=CTI_SYSTEM_PROMPT,
            )
            if ttp_result:
                from cti_sentinel.database.models import TTP
                for ttp_data in ttp_result.get("ttps", []):
                    mitre_id = ttp_data.get("technique_id", "")
                    if mitre_id and mitre_id.startswith("T"):
                        existing = session.query(TTP).filter_by(mitre_id=mitre_id).first()
                        if not existing:
                            ttp = TTP(
                                mitre_id=mitre_id,
                                name=ttp_data.get("technique_name", ""),
                                tactic=ttp_data.get("tactic", ""),
                            )
                            session.add(ttp)
                            session.flush()

        # ── Étape 6: Flashcards (optionnel) ───────────────────────────────
        if self.config.get("learning.flashcards.auto_generate", False):
            if article.severity in (SeverityLevel.CRITIQUE, SeverityLevel.HAUTE):
                await self._generate_flashcards(session, article)

    async def _generate_flashcards(self, session, article: Article):
        """Génère des flashcards éducatives à partir d'un article."""
        try:
            result = await self.llm.generate_json(
                prompt=FLASHCARD_GENERATION_PROMPT.format(
                    title=article.title,
                    content=(article.content or "")[:3000],
                ),
                system=CTI_SYSTEM_PROMPT,
            )
            if result and result.get("flashcards"):
                for fc_data in result["flashcards"]:
                    flashcard = Flashcard(
                        category=fc_data.get("category", "concept"),
                        question=fc_data.get("question", ""),
                        answer=fc_data.get("answer", ""),
                        difficulty=fc_data.get("difficulty", "intermédiaire"),
                        source_article_id=article.id,
                    )
                    session.add(flashcard)
        except Exception as e:
            logger.warning("Erreur génération flashcards: %s", str(e))

    @staticmethod
    def _basic_severity_scoring(title: str, content: str) -> SeverityLevel:
        """Scoring de sévérité basique par mots-clés (sans LLM)."""
        text = f"{title} {content}".lower()

        critical_keywords = [
            "0-day", "zero-day", "zeroday", "critical vulnerability", "rce",
            "remote code execution", "actively exploited", "ransomware attack",
            "data breach", "supply chain attack", "critical infrastructure",
        ]
        high_keywords = [
            "high severity", "cvss 9", "cvss 10", "exploit available",
            "apt", "advanced persistent", "campaign", "malware",
            "backdoor", "nation-state", "espionage",
        ]
        medium_keywords = [
            "vulnerability", "cve-", "phishing", "trojan", "botnet",
            "ddos", "brute force", "credential",
        ]

        for kw in critical_keywords:
            if kw in text:
                return SeverityLevel.CRITIQUE

        for kw in high_keywords:
            if kw in text:
                return SeverityLevel.HAUTE

        for kw in medium_keywords:
            if kw in text:
                return SeverityLevel.MOYENNE

        return SeverityLevel.INFO

    # Cache CISA KEV en mémoire (chargé une seule fois par session)
    _cisa_kev_cache: Optional[set] = None
    _cisa_kev_loaded_at: Optional[datetime] = None

    async def _get_cisa_kev_set(self) -> set:
        """
        Télécharge le catalogue CISA KEV UNE SEULE FOIS et le garde en mémoire.
        Le fichier fait ~2 MB — il ne faut surtout pas le re-télécharger pour chaque CVE.
        Le cache expire après 6 heures.
        """
        now = datetime.now(timezone.utc)
        if (
            self._cisa_kev_cache is not None
            and self._cisa_kev_loaded_at
            and (now - self._cisa_kev_loaded_at).total_seconds() < 21600  # 6h
        ):
            return self._cisa_kev_cache

        import aiohttp
        try:
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        ProcessingEngine._cisa_kev_cache = {
                            v.get("cveID", "").upper()
                            for v in data.get("vulnerabilities", [])
                        }
                        ProcessingEngine._cisa_kev_loaded_at = now
                        logger.info("✅ CISA KEV chargé: %d entrées", len(self._cisa_kev_cache))
                        return self._cisa_kev_cache
        except Exception as e:
            logger.warning("Erreur chargement CISA KEV: %s", str(e))

        return self._cisa_kev_cache or set()

    async def enrich_vulnerability(self, session, cve_id: str) -> Optional[Dict]:
        """
        Enrichit une CVE avec EPSS et vérification CISA KEV.
        - EPSS : appel individuel avec rate limiting (1 req/s)
        - CISA KEV : lookup dans le cache mémoire (téléchargé 1 seule fois)
        """
        import aiohttp

        enrichment = {}

        # EPSS Score — rate limité à 1 req/s pour respecter les ToS FIRST.org
        try:
            await asyncio.sleep(1)  # Rate limit explicite
            async with aiohttp.ClientSession() as http:
                async with http.get(
                    f"https://api.first.org/data/v1/epss?cve={cve_id}",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        if data.get("data"):
                            epss_data = data["data"][0]
                            enrichment["epss_score"] = float(epss_data.get("epss", 0))
                            enrichment["epss_percentile"] = float(epss_data.get("percentile", 0))
                    elif resp.status == 429:
                        logger.warning("EPSS rate limited, attente 60s")
                        await asyncio.sleep(60)
        except Exception as e:
            logger.debug("Erreur EPSS pour %s: %s", cve_id, str(e))

        # CISA KEV — lookup dans le cache (PAS de téléchargement par CVE)
        try:
            kev_set = await self._get_cisa_kev_set()
            enrichment["cisa_kev"] = cve_id.upper() in kev_set
        except Exception as e:
            logger.debug("Erreur CISA KEV pour %s: %s", cve_id, str(e))

        # Mettre à jour en DB
        if enrichment:
            from cti_sentinel.database.models import Vulnerability
            vuln = session.query(Vulnerability).filter_by(cve_id=cve_id).first()
            if vuln:
                for key, value in enrichment.items():
                    setattr(vuln, key, value)
                vuln.enriched_at = datetime.now(timezone.utc)

        return enrichment
