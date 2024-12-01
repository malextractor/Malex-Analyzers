# Utilisez une image Python légère comme base
FROM python:3.9-slim

# Définissez le répertoire de travail dans le conteneur
WORKDIR /app

# Copiez les fichiers nécessaires dans le conteneur
COPY remcos /app/modules/remcos
COPY requirements.txt /app/

# Installez les dépendances
RUN pip install --no-cache-dir -r requirements.txt

# Affiche les fichiers dans le conteneur pour vérifier le montage
RUN ls -l /app

# Commande par défaut pour exécuter malduck avec un argument
ENTRYPOINT ["malduck", "extract", "--modules", "modules/"]
