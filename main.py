#!/usr/bin/env python3
"""
CTI Sentinel - Point d'entrée principal.
Outil de veille CTI/Géopolitique local.

Usage:
    python main.py                    # Lance le scheduler complet
    python main.py collect            # Collecte manuelle unique
    python main.py collect --source nvd
    python main.py process            # Traitement LLM des articles en attente
    python main.py api                # Lance l'API REST
    python main.py dashboard          # Lance le dashboard Streamlit
    python main.py stats              # Affiche les statistiques
    python main.py backup             # Crée un backup
    python main.py init               # Initialise la base de données
"""

import argparse
import asyncio
import logging
import sys
import os

# Ajouter le répertoire parent au path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def setup_logging(verbose: bool = False):
    """Configure le logging."""
    os.makedirs("logs", exist_ok=True)
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler("logs/cti_sentinel.log"),
        ],
    )


def cmd_init(args):
    """Initialise la base de données et les répertoires."""
    from cti_sentinel.config import ConfigLoader
    from cti_sentinel.database.manager import DatabaseManager

    config = ConfigLoader()
    db = DatabaseManager(config)
    db.create_tables()
    print("✅ Base de données initialisée")
    print(f"   📁 DB: {config.get('database.url', 'sqlite:///data/cti_sentinel.db')}")


def cmd_collect(args):
    """Lance une collecte manuelle."""
    from cti_sentinel.config import ConfigLoader
    from cti_sentinel.database.manager import DatabaseManager
    from cti_sentinel.collectors.engine import CollectionEngine

    config = ConfigLoader()
    db = DatabaseManager(config)
    db.create_tables()
    engine = CollectionEngine(config, db)

    async def _collect():
        if args.source:
            print(f"🔄 Collecte de la source: {args.source}")
            await engine.collect_source(args.source)
        else:
            categories = args.categories.split(",") if args.categories else None
            cat_str = ", ".join(categories) if categories else "toutes"
            print(f"🔄 Collecte des catégories: {cat_str}")
            await engine.collect_all(categories=categories)
        print("✅ Collecte terminée")

    asyncio.run(_collect())


def cmd_process(args):
    """Lance le traitement des articles en attente."""
    from cti_sentinel.config import ConfigLoader
    from cti_sentinel.database.manager import DatabaseManager
    from cti_sentinel.processor.engine import ProcessingEngine

    config = ConfigLoader()
    db = DatabaseManager(config)
    engine = ProcessingEngine(config, db)

    async def _process():
        print(f"🤖 Traitement de {args.limit} articles en attente...")
        await engine.process_pending_articles(limit=args.limit)
        print("✅ Traitement terminé")

    asyncio.run(_process())


def cmd_api(args):
    """Lance le serveur API REST."""
    import uvicorn
    from cti_sentinel.config import ConfigLoader

    config = ConfigLoader()
    host = args.host or config.get("api.host", "0.0.0.0")
    port = args.port or config.get("api.port", 8000)

    print(f"🌐 Démarrage de l'API sur http://{host}:{port}")
    print(f"   📚 Documentation: http://{host}:{port}/docs")
    uvicorn.run("cti_sentinel.api.server:app", host=host, port=port, reload=args.reload)


def cmd_dashboard(args):
    """Lance le dashboard Streamlit."""
    import subprocess

    port = args.port or 8501
    print(f"📊 Démarrage du dashboard sur http://localhost:{port}")
    subprocess.run([
        sys.executable, "-m", "streamlit", "run",
        "cti_sentinel/dashboard/app.py",
        "--server.port", str(port),
        "--server.headless", "true",
        "--theme.base", "dark",
    ])


def cmd_scheduler(args):
    """Lance le scheduler complet."""
    from cti_sentinel.scheduler.scheduler import run_scheduler

    print("🚀 Démarrage de CTI Sentinel Scheduler...")
    print("   Ctrl+C pour arrêter")
    asyncio.run(run_scheduler())


def cmd_stats(args):
    """Affiche les statistiques."""
    from cti_sentinel.config import ConfigLoader
    from cti_sentinel.database.manager import DatabaseManager

    config = ConfigLoader()
    db = DatabaseManager(config)

    with db.get_session() as session:
        stats = db.get_dashboard_stats(session)

    print("\n" + "=" * 60)
    print("  📊 CTI SENTINEL - Statistiques")
    print("=" * 60)

    for category, data in stats.items():
        if isinstance(data, dict):
            total = data.get("total", 0)
            print(f"\n  {category.upper()}: {total}")
            for key, value in data.items():
                if key != "total":
                    print(f"    • {key}: {value}")

    print("\n" + "=" * 60)


def cmd_backup(args):
    """Crée un backup de la base de données."""
    from cti_sentinel.config import ConfigLoader
    from cti_sentinel.database.manager import DatabaseManager

    config = ConfigLoader()
    db = DatabaseManager(config)
    path = db.backup()
    print(f"💾 Backup créé: {path}")


def cmd_export(args):
    """Exporte les données."""
    from cti_sentinel.config import ConfigLoader
    from cti_sentinel.database.manager import DatabaseManager
    from cti_sentinel.analyzer.correlation import CorrelationEngine

    config = ConfigLoader()
    db = DatabaseManager(config)
    correlation = CorrelationEngine(config, db)

    with db.get_session() as session:
        if args.format == "stix":
            import json
            bundle = correlation.export_stix_bundle(session, days=args.days)
            output = args.output or f"export_stix_{args.days}d.json"
            with open(output, "w") as f:
                json.dump(bundle, f, indent=2)
            print(f"📦 Export STIX sauvegardé: {output}")
        else:
            print(f"Format '{args.format}' non supporté. Utilisez: stix")


def main():
    """Point d'entrée principal."""
    parser = argparse.ArgumentParser(
        description="🛡️ CTI Sentinel - Outil de veille CTI/Géopolitique",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples:
  python main.py init                      Initialiser la base de données
  python main.py collect                   Collecte complète
  python main.py collect --source nvd      Collecte NVD uniquement
  python main.py process --limit 50        Traiter 50 articles
  python main.py api                       Lancer l'API REST
  python main.py dashboard                 Lancer le dashboard
  python main.py stats                     Voir les statistiques
  python main.py backup                    Créer un backup
  python main.py export --format stix      Export STIX 2.1
        """,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Mode verbose")

    subparsers = parser.add_subparsers(dest="command", help="Commande à exécuter")

    # init
    subparsers.add_parser("init", help="Initialiser la base de données")

    # collect
    p_collect = subparsers.add_parser("collect", help="Lancer une collecte")
    p_collect.add_argument("--source", help="Source spécifique à collecter")
    p_collect.add_argument("--categories", help="Catégories (séparées par des virgules)")

    # process
    p_process = subparsers.add_parser("process", help="Traiter les articles")
    p_process.add_argument("--limit", type=int, default=100, help="Nombre max d'articles")

    # api
    p_api = subparsers.add_parser("api", help="Lancer l'API REST")
    p_api.add_argument("--host", default=None, help="Adresse d'écoute")
    p_api.add_argument("--port", type=int, default=None, help="Port d'écoute")
    p_api.add_argument("--reload", action="store_true", help="Mode rechargement auto")

    # dashboard
    p_dash = subparsers.add_parser("dashboard", help="Lancer le dashboard")
    p_dash.add_argument("--port", type=int, default=None, help="Port du dashboard")

    # scheduler
    subparsers.add_parser("scheduler", help="Lancer le scheduler complet")

    # stats
    subparsers.add_parser("stats", help="Afficher les statistiques")

    # backup
    subparsers.add_parser("backup", help="Créer un backup")

    # export
    p_export = subparsers.add_parser("export", help="Exporter les données")
    p_export.add_argument("--format", default="stix", help="Format d'export")
    p_export.add_argument("--days", type=int, default=7, help="Période en jours")
    p_export.add_argument("--output", help="Fichier de sortie")

    args = parser.parse_args()
    setup_logging(args.verbose)

    commands = {
        "init": cmd_init,
        "collect": cmd_collect,
        "process": cmd_process,
        "api": cmd_api,
        "dashboard": cmd_dashboard,
        "scheduler": cmd_scheduler,
        "stats": cmd_stats,
        "backup": cmd_backup,
        "export": cmd_export,
    }

    if args.command:
        commands[args.command](args)
    else:
        # Sans commande = scheduler par défaut
        cmd_scheduler(args)


if __name__ == "__main__":
    main()
