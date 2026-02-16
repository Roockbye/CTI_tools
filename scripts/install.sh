#!/bin/bash
# ============================================================================
# CTI Sentinel - Script d'installation
# ============================================================================

set -e

echo "🛡️  CTI Sentinel - Installation"
echo "================================"

# Vérifier Python 3.10+
PYTHON_CMD=""
if command -v python3 &>/dev/null; then
    PYTHON_CMD="python3"
elif command -v python &>/dev/null; then
    PYTHON_CMD="python"
else
    echo "❌ Python 3.10+ requis. Installez Python d'abord."
    exit 1
fi

PY_VERSION=$($PYTHON_CMD -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "✅ Python $PY_VERSION détecté"

# Créer l'environnement virtuel
echo ""
echo "📦 Création de l'environnement virtuel..."
$PYTHON_CMD -m venv venv
source venv/bin/activate

# Installer les dépendances
echo ""
echo "📥 Installation des dépendances..."
pip install --upgrade pip
pip install -r requirements.txt

# Créer les répertoires
echo ""
echo "📁 Création des répertoires..."
mkdir -p data logs cache backups export config

# Copier la configuration
if [ ! -f ".env" ]; then
    cp .env.example .env
    echo "📝 Fichier .env créé (éditez-le avec vos clés API)"
fi

# Initialiser la base de données
echo ""
echo "🗄️  Initialisation de la base de données..."
python main.py init

# Vérifier Ollama
echo ""
if command -v ollama &>/dev/null; then
    echo "✅ Ollama détecté"
    echo "   Téléchargement du modèle Mistral..."
    ollama pull mistral:7b || echo "⚠️  Échec du pull Mistral (lancez 'ollama pull mistral:7b' manuellement)"
else
    echo "⚠️  Ollama non détecté"
    echo "   Installez Ollama: https://ollama.ai"
    echo "   Puis: ollama pull mistral:7b"
fi

echo ""
echo "============================================"
echo "✅ Installation terminée !"
echo ""
echo "📝 Prochaines étapes:"
echo "   1. Éditez .env avec vos clés API"
echo "   2. Éditez config/config.yaml si nécessaire"
echo "   3. Lancez: python main.py"
echo ""
echo "Commandes disponibles:"
echo "   python main.py init         Initialiser la DB"
echo "   python main.py collect      Collecte manuelle"
echo "   python main.py process      Traitement LLM"
echo "   python main.py api          API REST (port 8000)"
echo "   python main.py dashboard    Dashboard (port 8501)"
echo "   python main.py scheduler    Scheduler complet"
echo "   python main.py stats        Statistiques"
echo "============================================"
