"""
Scheduler - Automatisation des tâches CTI Sentinel.
Gère la collecte périodique, le traitement, les alertes, backups et nettoyage.
"""

import asyncio
import logging
import signal
import sys
from datetime import datetime, timezone
from typing import Optional

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from cti_sentinel.config import ConfigLoader
from cti_sentinel.database.manager import DatabaseManager
from cti_sentinel.collectors.engine import CollectionEngine
from cti_sentinel.processor.engine import ProcessingEngine
from cti_sentinel.analyzer.correlation import CorrelationEngine
from cti_sentinel.alerts.manager import AlertManager

logger = logging.getLogger(__name__)


class CTIScheduler:
    """Planificateur de tâches automatisées CTI Sentinel."""

    def __init__(self, config: Optional[ConfigLoader] = None):
        self.config = config or ConfigLoader()
        self.db = DatabaseManager(self.config)
        self.db.create_tables()

        self.collection_engine = CollectionEngine(self.config, self.db)
        self.processing_engine = ProcessingEngine(self.config, self.db)
        self.correlation_engine = CorrelationEngine(self.config, self.db)
        self.alert_manager = AlertManager(self.config, self.db)

        self.scheduler = AsyncIOScheduler(
            timezone="UTC",
            job_defaults={
                "coalesce": True,
                "max_instances": 1,
                "misfire_grace_time": 300,
            },
        )
        self._running = False

    # ========================================================================
    # Tâches planifiées
    # ========================================================================

    async def task_collect_high_frequency(self):
        """Collecte haute fréquence (toutes les 30 min) - RSS critiques."""
        logger.info("⏰ [Scheduler] Collecte haute fréquence démarrée")
        try:
            await self.collection_engine.collect_all(categories=["cert", "news"])
            logger.info("✅ [Scheduler] Collecte haute fréquence terminée")
        except Exception as e:
            logger.error(f"❌ [Scheduler] Erreur collecte haute fréquence: {e}")

    async def task_collect_medium_frequency(self):
        """Collecte moyenne fréquence (toutes les 2h) - APIs vulnérabilités."""
        logger.info("⏰ [Scheduler] Collecte moyenne fréquence démarrée")
        try:
            await self.collection_engine.collect_all(categories=["vulnerability", "threat_intel"])
            logger.info("✅ [Scheduler] Collecte moyenne fréquence terminée")
        except Exception as e:
            logger.error(f"❌ [Scheduler] Erreur collecte moyenne fréquence: {e}")

    async def task_collect_low_frequency(self):
        """Collecte basse fréquence (toutes les 6h) - Bases CTI complètes."""
        logger.info("⏰ [Scheduler] Collecte basse fréquence démarrée")
        try:
            await self.collection_engine.collect_all(categories=["mitre", "abuse_ch"])
            logger.info("✅ [Scheduler] Collecte basse fréquence terminée")
        except Exception as e:
            logger.error(f"❌ [Scheduler] Erreur collecte basse fréquence: {e}")

    async def task_process_articles(self):
        """Traitement LLM des articles en attente."""
        logger.info("🤖 [Scheduler] Traitement des articles démarré")
        try:
            limit = self.config.get("scheduler.processing_batch_size", 50)
            await self.processing_engine.process_pending_articles(limit=limit)
            logger.info("✅ [Scheduler] Traitement des articles terminé")
        except Exception as e:
            logger.error(f"❌ [Scheduler] Erreur traitement: {e}")

    async def task_evaluate_alerts(self):
        """Évaluation des alertes sur les nouveaux articles."""
        logger.info("🔔 [Scheduler] Évaluation des alertes démarrée")
        try:
            from cti_sentinel.database.models import Article, ArticleStatus
            with self.db.get_session() as session:
                # Articles traités non encore évalués pour alertes
                recent = (
                    session.query(Article)
                    .filter(Article.status == ArticleStatus.processed)
                    .order_by(Article.collected_at.desc())
                    .limit(100)
                    .all()
                )
                for article in recent:
                    await self.alert_manager.evaluate_article(session, article)
            logger.info(f"✅ [Scheduler] {len(recent)} articles évalués pour alertes")
        except Exception as e:
            logger.error(f"❌ [Scheduler] Erreur alertes: {e}")

    async def task_daily_digest(self):
        """Envoi du digest quotidien."""
        logger.info("📧 [Scheduler] Envoi du digest quotidien")
        try:
            with self.db.get_session() as session:
                await self.alert_manager.send_daily_digest(session)
            logger.info("✅ [Scheduler] Digest quotidien envoyé")
        except Exception as e:
            logger.error(f"❌ [Scheduler] Erreur digest: {e}")

    async def task_backup(self):
        """Backup quotidien de la base de données."""
        logger.info("💾 [Scheduler] Backup démarré")
        try:
            backup_path = self.db.backup()
            logger.info(f"✅ [Scheduler] Backup créé: {backup_path}")
        except Exception as e:
            logger.error(f"❌ [Scheduler] Erreur backup: {e}")

    async def task_cleanup(self):
        """Nettoyage hebdomadaire des données anciennes."""
        logger.info("🧹 [Scheduler] Nettoyage démarré")
        try:
            retention_days = self.config.get("scheduler.retention_days", 90)
            with self.db.get_session() as session:
                deleted = self.db.cleanup_old_data(session, days=retention_days)
            logger.info(f"✅ [Scheduler] Nettoyage terminé: {deleted} entrées supprimées")
        except Exception as e:
            logger.error(f"❌ [Scheduler] Erreur nettoyage: {e}")

    async def task_enrich_vulnerabilities(self):
        """Enrichissement EPSS/CISA KEV des vulnérabilités."""
        logger.info("🔍 [Scheduler] Enrichissement des vulnérabilités démarré")
        try:
            from cti_sentinel.database.models import Vulnerability
            with self.db.get_session() as session:
                vulns = (
                    session.query(Vulnerability)
                    .filter(Vulnerability.epss_score == None)
                    .limit(50)
                    .all()
                )
                for vuln in vulns:
                    await self.processing_engine.enrich_vulnerability(session, vuln)
            logger.info(f"✅ [Scheduler] {len(vulns)} vulnérabilités enrichies")
        except Exception as e:
            logger.error(f"❌ [Scheduler] Erreur enrichissement: {e}")

    # ========================================================================
    # Configuration du scheduler
    # ========================================================================

    def setup_jobs(self):
        """Configure tous les jobs planifiés."""
        sched_config = self.config.get("scheduler", {})

        # Collecte haute fréquence - toutes les 60 min (respectueux des serveurs)
        high_freq = sched_config.get("high_frequency_minutes", 60)
        self.scheduler.add_job(
            self.task_collect_high_frequency,
            IntervalTrigger(minutes=high_freq),
            id="collect_high",
            name="Collecte haute fréquence",
        )

        # Collecte moyenne fréquence - toutes les 2h
        med_freq = sched_config.get("medium_frequency_minutes", 120)
        self.scheduler.add_job(
            self.task_collect_medium_frequency,
            IntervalTrigger(minutes=med_freq),
            id="collect_medium",
            name="Collecte moyenne fréquence",
        )

        # Collecte basse fréquence - toutes les 6h
        low_freq = sched_config.get("low_frequency_minutes", 360)
        self.scheduler.add_job(
            self.task_collect_low_frequency,
            IntervalTrigger(minutes=low_freq),
            id="collect_low",
            name="Collecte basse fréquence",
        )

        # Traitement LLM - toutes les 15 min
        process_freq = sched_config.get("processing_frequency_minutes", 15)
        self.scheduler.add_job(
            self.task_process_articles,
            IntervalTrigger(minutes=process_freq),
            id="process",
            name="Traitement LLM",
        )

        # Alertes - toutes les 10 min
        alert_freq = sched_config.get("alert_frequency_minutes", 10)
        self.scheduler.add_job(
            self.task_evaluate_alerts,
            IntervalTrigger(minutes=alert_freq),
            id="alerts",
            name="Évaluation alertes",
        )

        # Digest quotidien - 08:00 UTC
        digest_hour = sched_config.get("digest_hour", 8)
        self.scheduler.add_job(
            self.task_daily_digest,
            CronTrigger(hour=digest_hour, minute=0),
            id="digest",
            name="Digest quotidien",
        )

        # Enrichissement vulnérabilités - toutes les 4h
        self.scheduler.add_job(
            self.task_enrich_vulnerabilities,
            IntervalTrigger(hours=4),
            id="enrich_vulns",
            name="Enrichissement vulnérabilités",
        )

        # Backup quotidien - 02:00 UTC
        backup_hour = sched_config.get("backup_hour", 2)
        self.scheduler.add_job(
            self.task_backup,
            CronTrigger(hour=backup_hour, minute=0),
            id="backup",
            name="Backup quotidien",
        )

        # Nettoyage hebdomadaire - dimanche 03:00 UTC
        self.scheduler.add_job(
            self.task_cleanup,
            CronTrigger(day_of_week="sun", hour=3, minute=0),
            id="cleanup",
            name="Nettoyage hebdomadaire",
        )

        logger.info(f"📋 {len(self.scheduler.get_jobs())} jobs planifiés configurés")

    # ========================================================================
    # Gestion du cycle de vie
    # ========================================================================

    async def start(self, run_initial_collection: bool = True):
        """Démarre le scheduler."""
        logger.info("🚀 Démarrage de CTI Sentinel Scheduler...")

        self.setup_jobs()
        self.scheduler.start()
        self._running = True

        # Collecte initiale au démarrage
        if run_initial_collection:
            logger.info("🔄 Collecte initiale au démarrage...")
            await self.task_collect_high_frequency()
            await self.task_process_articles()
            await self.task_evaluate_alerts()

        logger.info("✅ CTI Sentinel Scheduler en cours d'exécution")

        # Afficher les jobs planifiés
        for job in self.scheduler.get_jobs():
            next_run = job.next_run_time
            logger.info(f"  📌 {job.name} → Prochaine exécution: {next_run}")

    async def stop(self):
        """Arrête le scheduler proprement."""
        logger.info("⏹️ Arrêt de CTI Sentinel Scheduler...")
        self._running = False
        self.scheduler.shutdown(wait=True)
        logger.info("✅ Scheduler arrêté proprement")

    def get_status(self) -> dict:
        """Retourne le statut du scheduler."""
        jobs = []
        for job in self.scheduler.get_jobs():
            jobs.append({
                "id": job.id,
                "name": job.name,
                "next_run": str(job.next_run_time) if job.next_run_time else None,
                "pending": job.pending,
            })
        return {
            "running": self._running,
            "jobs": jobs,
            "job_count": len(jobs),
        }


# ============================================================================
# Point d'entrée CLI
# ============================================================================

async def run_scheduler():
    """Exécute le scheduler en mode daemon."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("logs/scheduler.log"),
        ],
    )

    scheduler = CTIScheduler()
    loop = asyncio.get_event_loop()

    def shutdown_handler(sig, frame):
        logger.info(f"Signal {sig} reçu, arrêt en cours...")
        loop.create_task(scheduler.stop())

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    await scheduler.start()

    # Maintenir le processus actif
    try:
        while scheduler._running:
            await asyncio.sleep(1)
    except (KeyboardInterrupt, SystemExit):
        await scheduler.stop()


if __name__ == "__main__":
    asyncio.run(run_scheduler())
