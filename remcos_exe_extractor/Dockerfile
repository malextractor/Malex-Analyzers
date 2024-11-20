# Utilise une image de base Python
FROM python:3.9-slim

# Configure le répertoire de travail
WORKDIR /app

# Copie le script Python dans le conteneur
COPY extract_config.py /app/

# Met à jour pip et installe les dépendances directement
RUN python -m pip install --upgrade pip && \
    pip install --no-cache-dir pefile regex arc4

# Définit les arguments par défaut pour le script
ARG FILES
ARG VERBOSE=0

# Définit la commande par défaut pour exécuter le script avec les arguments
ENTRYPOINT ["python", "extract_config.py"]
CMD ["-v", "$VERBOSE", "$FILES"]
