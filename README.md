# 🛡️ CTI Sentinel

**Outil de veille CTI (Cyber Threat Intelligence) et Géopolitique — 100% local**

[![Python 3.10+](https://img.shields.io/badge/Python-3.10+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/API-FastAPI-009688.svg)](https://fastapi.tiangolo.com)
[![Streamlit](https://img.shields.io/badge/Dashboard-Streamlit-FF4B4B.svg)](https://streamlit.io)
[![Ollama](https://img.shields.io/badge/LLM-Ollama-white.svg)](https://ollama.ai)

---

## 📋 Sommaire

- [Présentation](#-présentation)
- [Architecture](#-architecture)
- [Fonctionnalités](#-fonctionnalités)
- [Installation](#-installation)
- [Configuration](#-configuration)
- [Utilisation](#-utilisation)
- [API REST](#-api-rest)
- [Dashboard](#-dashboard)
- [Docker](#-docker)
- [Sources de données](#-sources-de-données)

---

## 🎯 Présentation

CTI Sentinel est un outil **100% local** de veille en cybersécurité et géopolitique, conçu pour l'apprentissage et la formation personnelle en CTI. Il collecte, traite et corrèle automatiquement les informations de menaces provenant de multiples sources ouvertes.

Interface	URL
Dashboard	http://localhost:8501
API Swagger	http://localhost:8000/docs
API ReDoc	http://localhost:8000/redoc

### Pourquoi CTI Sentinel ?

- 🔒 **100% local** — Aucune donnée envoyée vers le cloud (sauf les API publiques de collecte)
- 🤖 **LLM local** — Traitement intelligent via Ollama (Mistral/Llama3)
- 🇫🇷 **Interface en français** — Résumés et dashboard en français
- 📚 **Mode apprentissage** — Flashcards et quiz pour progresser en CTI
- 🔄 **Automatisé** — Collecte et traitement planifiés automatiquement

---

## 🏗️ Architecture

```
CTI Sentinel
├── 📡 Collecteurs          30+ sources (RSS, APIs, MITRE ATT&CK)
│   ├── RSS/Atom            CERT-FR, BleepingComputer, KrebsOnSecurity...
│   ├── APIs                NVD, AlienVault OTX, abuse.ch, MITRE
│   └── Engine              Orchestration parallèle avec rate limiting
│
├── 🤖 Processeur LLM       Analyse intelligente via Ollama
│   ├── IOC Extractor       Extraction regex (14 types d'IOC)
│   ├── LLM Client          Scoring sévérité, résumés FR, TTPs
│   └── Pipeline            Traitement en 6 étapes
│
├── 🗄️ Base de données      SQLAlchemy + SQLite/PostgreSQL
│   ├── 14 modèles          Articles, CVE, IOC, Acteurs, Malware, TTP...
│   └── 13 relations M2M    Corrélation complète entre entités
│
├── 🔍 Analyseur            Corrélation et tendances
│   ├── Graphe d'entités    Relations entre acteurs, malwares, campagnes
│   ├── Tendances           Détection de patterns et scoring
│   ├── MITRE Heatmap       Matrice ATT&CK visuelle
│   └── Export STIX 2.1     Standard de partage CTI
│
├── 🔔 Alertes              Notifications multi-canal
│   ├── Desktop             Linux/macOS/Windows
│   ├── Discord/Slack       Webhooks avec embeds
│   ├── Telegram            Bot API
│   └── Email               SMTP
│
├── 🌐 API REST             FastAPI avec documentation Swagger
│   ├── CRUD complet        Articles, CVE, IOC, Acteurs
│   ├── Analyse             Timeline, tendances, graphe, heatmap
│   └── Export              STIX 2.1, CSV, JSON, TXT
│
├── 📊 Dashboard            Streamlit avec Plotly
│   ├── Vue d'ensemble      KPIs, score de menace, articles critiques
│   ├── Visualisations      Timeline, heatmap MITRE, graphe
│   └── Apprentissage       Flashcards interactives
│
└── ⏰ Scheduler            APScheduler
    ├── Multi-fréquence     30min / 2h / 6h selon les sources
    ├── Maintenance          Backup, nettoyage, enrichissement
    └── Digest               Rapport quotidien
```

---

## ✨ Fonctionnalités

| Module | Fonctionnalité | Détails |
|--------|---------------|---------|
| 📡 Collecte | 30+ sources | RSS, NVD, OTX, abuse.ch, MITRE ATT&CK |
| 🤖 LLM | Analyse automatique | Scoring sévérité, résumés FR, extraction IOC/TTP |
| 🔍 IOC | 14 types supportés | IPv4/6, hashes, domaines, URLs, CVE, emails... |
| 📊 Analyse | Corrélation | Graphe d'entités, tendances, scoring par secteur |
| 🗺️ MITRE | Heatmap ATT&CK | Matrice tactique × technique |
| 🔔 Alertes | 5 canaux | Desktop, Discord, Telegram, Slack, Email |
| 📦 Export | Standards | STIX 2.1, CSV, JSON |
| 🎓 Learning | Flashcards | Quiz adaptatifs générés par LLM |

---

## 🚀 Installation

### Prérequis

- **Python 3.10+**
- **Ollama** avec un modèle (Mistral 7B recommandé)
- Git

### Installation rapide

```bash
# Cloner le projet
git clone https://github.com/Roockbye/CTI_tools.git
cd CTI_tools

# Script d'installation automatique
chmod +x scripts/install.sh
./scripts/install.sh
```

### Installation manuelle

```bash
# Environnement virtuel
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# Dépendances
pip install -r requirements.txt

# Configuration
cp .env.example .env
# Éditez .env avec vos clés API

# Initialisation
python main.py init

# Installer Ollama + modèle
# https://ollama.ai
ollama pull mistral:7b
```

---

## ⚙️ Configuration

### Fichier `.env`

```bash
# Clés API (optionnelles mais recommandées)
NVD_API_KEY=votre_cle_nvd        # https://nvd.nist.gov/developers/request-an-api-key
OTX_API_KEY=votre_cle_otx        # https://otx.alienvault.com

# Notifications (optionnel)
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
TELEGRAM_BOT_TOKEN=votre_token
TELEGRAM_CHAT_ID=votre_chat_id
```

### Fichier `config/config.yaml`

Le fichier de configuration principal permet de personnaliser :
- **Sources** — Activer/désactiver des flux RSS et APIs
- **LLM** — Modèle Ollama, températures, timeouts
- **Alertes** — Règles de notification, canaux, cooldown
- **Scheduler** — Fréquences de collecte
- **Technologies surveillées** — Produits et secteurs à surveiller

---

## 🖥️ Utilisation

### Commandes CLI

```bash
# Démarrer le scheduler complet (mode daemon)
python main.py

# Collecte manuelle
python main.py collect                      # Toutes les sources
python main.py collect --source nvd         # Source spécifique
python main.py collect --categories cert,news  # Par catégorie

# Traitement LLM
python main.py process                      # Traiter les articles en attente
python main.py process --limit 50           # Limiter à 50 articles

# Services
python main.py api                          # API REST (port 8000)
python main.py api --port 9000 --reload     # Port custom + hot reload
python main.py dashboard                    # Dashboard (port 8501)

# Opérations
python main.py stats                        # Statistiques
python main.py backup                       # Backup base de données
python main.py export --format stix         # Export STIX 2.1
```

### Workflow typique

```bash
# 1. Premier lancement
python main.py init
python main.py collect
python main.py process

# 2. Consulter les résultats
python main.py stats
python main.py api &         # API en arrière-plan
python main.py dashboard     # Dashboard

# 3. Mode automatique
python main.py               # Scheduler complet
```

---

## 🌐 API REST

L'API REST est documentée automatiquement via Swagger UI.

**URL**: `http://localhost:8000/docs`

### Endpoints principaux

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/api/stats` | Statistiques globales |
| GET | `/api/threat-score` | Score de menace |
| GET | `/api/articles` | Liste des articles (filtres avancés) |
| GET | `/api/articles/{id}` | Détail d'un article |
| GET | `/api/vulnerabilities` | Liste des CVE |
| GET | `/api/vulnerabilities/{cve}` | Détail d'une CVE |
| GET | `/api/iocs` | Liste des IOCs |
| GET | `/api/iocs/search?value=...` | Recherche d'IOC |
| GET | `/api/threat-actors` | Groupes de menaces |
| GET | `/api/timeline` | Timeline des événements |
| GET | `/api/trends` | Tendances et patterns |
| GET | `/api/mitre-heatmap` | Heatmap MITRE ATT&CK |
| GET | `/api/graph` | Graphe de corrélation |
| POST | `/api/collect` | Lancer une collecte |
| POST | `/api/process` | Lancer le traitement |
| GET | `/api/export/stix` | Export STIX 2.1 |
| GET | `/api/export/iocs` | Export IOCs (JSON/CSV/TXT) |
| GET | `/api/flashcards` | Flashcards d'apprentissage |

---

## 📊 Dashboard

Le dashboard Streamlit offre 10 vues :

1. **📊 Vue d'ensemble** — KPIs, score de menace, articles critiques
2. **📰 Articles** — Recherche, filtres, lecture, favoris
3. **🔓 Vulnérabilités** — CVE avec CVSS, EPSS, exploits
4. **🔍 IOCs** — Recherche et listing par type
5. **👤 Threat Actors** — Profils détaillés des groupes
6. **📈 Tendances** — Patterns et acteurs les plus actifs
7. **🗺️ MITRE ATT&CK** — Heatmap tactique × technique
8. **🕸️ Graphe** — Relations entre entités
9. **🎓 Apprentissage** — Flashcards interactives
10. **⚙️ Opérations** — Sources, exports, maintenance

---

## 🐳 Docker

### Déploiement complet

```bash
# Construire et lancer
docker-compose up -d

# Services lancés:
# - Ollama (LLM)      → port 11434
# - API REST           → port 8000
# - Dashboard          → port 8501
# - Scheduler          → arrière-plan
```

### Sans GPU (CPU uniquement)

Commentez le bloc `deploy.resources` dans `docker-compose.yml` pour le service Ollama.

---

## 📡 Sources de données

### RSS / Atom
| Source | Catégorie | Fréquence |
|--------|-----------|-----------|
| CERT-FR | Alertes officielles | 30 min |
| BleepingComputer | News cyber | 30 min |
| The Hacker News | News cyber | 30 min |
| KrebsOnSecurity | Investigations | 30 min |
| Dark Reading | News sécu | 30 min |
| Schneier on Security | Analyses | 30 min |
| CyberScoop | News politique/cyber | 30 min |
| The Record | News cyber | 30 min |
| SecurityAffairs | News cyber | 30 min |
| Mandiant Blog | Threat Intel | 30 min |
| CrowdStrike Blog | Threat Intel | 30 min |
| SentinelOne Blog | Recherche | 30 min |
| Talos Intelligence | Threat Intel | 30 min |
| Exploit-DB | Exploits | 30 min |

### APIs
| Source | Type | Fréquence |
|--------|------|-----------|
| NVD (NIST) | Vulnérabilités CVE | 2h |
| AlienVault OTX | IOCs & Pulses | 2h |
| URLhaus (abuse.ch) | URLs malveillantes | 2h |
| MalwareBazaar | Samples malware | 2h |
| ThreatFox | IOCs avec contexte | 2h |
| MITRE ATT&CK | TTPs & Groupes | 6h |

---

## 📁 Structure du projet

```
CTI_tools/
├── main.py                          # Point d'entrée CLI
├── requirements.txt                 # Dépendances Python
├── Dockerfile                       # Image Docker
├── docker-compose.yml               # Déploiement multi-services
├── .env.example                     # Template variables d'environnement
├── .gitignore
├── config/
│   └── config.yaml                  # Configuration centrale
├── scripts/
│   └── install.sh                   # Script d'installation
├── cti_sentinel/
│   ├── __init__.py
│   ├── config.py                    # Chargement configuration
│   ├── database/
│   │   ├── models.py                # 14 modèles SQLAlchemy
│   │   └── manager.py               # CRUD & gestion BDD
│   ├── collectors/
│   │   ├── base.py                  # Collecteur abstrait + cache
│   │   ├── rss_collector.py         # Collecteur RSS/Atom
│   │   ├── api_collectors.py        # NVD, OTX, abuse.ch, MITRE
│   │   └── engine.py                # Orchestrateur de collecte
│   ├── processor/
│   │   ├── llm_client.py            # Client Ollama + prompts CTI
│   │   ├── ioc_extractor.py         # Extraction IOC par regex
│   │   └── engine.py                # Pipeline de traitement
│   ├── analyzer/
│   │   └── correlation.py           # Corrélation, tendances, STIX
│   ├── alerts/
│   │   └── manager.py               # Alertes multi-canal
│   ├── api/
│   │   └── server.py                # API REST FastAPI
│   ├── dashboard/
│   │   └── app.py                   # Dashboard Streamlit
│   └── scheduler/
│       └── scheduler.py             # Planificateur APScheduler
├── data/                            # Base de données SQLite
├── logs/                            # Logs applicatifs
├── cache/                           # Cache des requêtes HTTP
└── backups/                         # Sauvegardes automatiques
```

---

## 🔧 Technologies

| Composant | Technologie |
|-----------|------------|
| Langage | Python 3.10+ |
| BDD | SQLAlchemy + SQLite (WAL) / PostgreSQL |
| API | FastAPI + Uvicorn |
| Dashboard | Streamlit + Plotly |
| LLM | Ollama (Mistral 7B / Llama3 8B) |
| Scheduler | APScheduler |
| HTTP | aiohttp (async) |
| RSS | feedparser |
| Conteneurs | Docker + Docker Compose |

---

## 📜 Licence

Projet personnel pour formation CTI. Usage éducatif.

---

## 🤝 Contribution

Ce projet est conçu pour l'apprentissage personnel. Les suggestions et améliorations sont les bienvenues via Issues et Pull Requests.

---

*Développé avec ❤️ pour la communauté CTI francophone*
