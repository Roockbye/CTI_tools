"""
Configuration Loader - Chargement et validation de la configuration.
"""

import os
import yaml
from pathlib import Path
from typing import Any, Optional
from dotenv import load_dotenv
import logging

logger = logging.getLogger(__name__)


class ConfigLoader:
    """Charge et valide la configuration depuis config.yaml et .env"""

    _instance: Optional["ConfigLoader"] = None
    _config: dict = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._config:
            self.load()

    def load(self, config_path: str = None):
        """Charge la configuration depuis le fichier YAML et les variables d'environnement."""
        # Charger .env
        project_root = Path(__file__).parent.parent
        env_path = project_root / ".env"
        if env_path.exists():
            load_dotenv(env_path)
        else:
            env_example = project_root / ".env.example"
            if env_example.exists():
                load_dotenv(env_example)

        # Charger config.yaml
        if config_path is None:
            config_path = project_root / "config" / "config.yaml"

        config_path = Path(config_path)
        if not config_path.exists():
            raise FileNotFoundError(f"Fichier de configuration introuvable: {config_path}")

        with open(config_path, "r", encoding="utf-8") as f:
            raw_config = yaml.safe_load(f)

        # Résoudre les variables d'environnement ${VAR_NAME}
        self._config = self._resolve_env_vars(raw_config)

        # Créer les répertoires nécessaires
        self._ensure_directories()

        logger.info("Configuration chargée avec succès depuis %s", config_path)

    def _resolve_env_vars(self, obj: Any) -> Any:
        """Résout récursivement les variables ${ENV_VAR} dans la configuration."""
        if isinstance(obj, str):
            if obj.startswith("${") and obj.endswith("}"):
                env_var = obj[2:-1]
                return os.getenv(env_var, "")
            return obj
        elif isinstance(obj, dict):
            return {k: self._resolve_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._resolve_env_vars(item) for item in obj]
        return obj

    def _ensure_directories(self):
        """Crée les répertoires nécessaires s'ils n'existent pas."""
        dirs = ["data_dir", "logs_dir", "reports_dir", "exports_dir", "cache_dir"]
        project_root = Path(__file__).parent.parent

        for dir_key in dirs:
            dir_path = self.get(f"general.{dir_key}", f"./{dir_key.replace('_dir', '')}")
            full_path = project_root / dir_path
            full_path.mkdir(parents=True, exist_ok=True)

        # Backup dir
        backup_path = self.get("database.backup.path", "./data/backups")
        (project_root / backup_path).mkdir(parents=True, exist_ok=True)

    def get(self, key: str, default: Any = None) -> Any:
        """
        Récupère une valeur de configuration par clé pointée.
        Ex: config.get("llm.ollama.model") -> "mistral:7b"
        """
        keys = key.split(".")
        value = self._config
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        return value

    def get_source_config(self, category: str, source_name: str) -> dict:
        """Récupère la configuration d'une source spécifique."""
        return self.get(f"sources.{category}.{source_name}", {})

    def get_enabled_sources(self) -> list:
        """Retourne la liste de toutes les sources activées."""
        sources = []
        sources_config = self.get("sources", {})
        for category, category_sources in sources_config.items():
            if isinstance(category_sources, dict):
                for name, config in category_sources.items():
                    if isinstance(config, dict) and config.get("enabled", False):
                        sources.append({
                            "category": category,
                            "name": name,
                            "config": config
                        })
        return sources

    def get_alert_rules(self) -> list:
        """Retourne les règles d'alertes configurées."""
        return self.get("alerts.rules", [])

    def get_watched_technologies(self) -> list:
        """Retourne la liste des technologies surveillées."""
        return self.get("watched_technologies", [])

    @property
    def config(self) -> dict:
        return self._config


# Instance globale
config = ConfigLoader()
