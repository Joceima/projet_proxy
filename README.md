


# Liste des fichiers 
proxy.py - Fichier principal contenant la gestion des requêtes HTTPS et HTTPS— 
configHandler.py - Gestion de la configuration— 
admin.py - Permet de lancer une page de configuration admin— 
mitmpproxy.py - Implémentation du MITM pour HTTPS— 
cache/ - Dossier contenant le cache— proxy_config.txt - Fichier de configuration texte2.2  

# Commandes sur Linux
python3 proxy.py - Permet de lancer le proxy HTTP/HTTPS.
python3 admin.py - Permet de lancer la configutation du filtrage côté admin.


# proxy.py
filtrer_contenu_html(headers: str, body: bytes)→ (bytes, bytes) Filtre le contenuHTML d’une requête HTTP selon les règles de configuration.

gere_requete_HTTP(client_socket, requete) Gère une requête HTTP entrante.filtrer_contenu_HTTPS(data) Filtrer le contenu HTTPS.

gere_requete_HTTPS(client_socket, requete) Gère une requête HTTPS (générationd’un certificat et d’une clé).

gere_requete_HTTPS_simple(client_socket, requete) Connexion tunnel simple client/-serveur HTTPS.

gerer_client(client_socket) Permet d’appeler les fonctions correspondantes si c’estqu’une requête HTTP ou HTTPS.

analyser_requete(requete_bytes) Permet d’analyser une requête en affichant dans leterminal les informations.

save_to_cache(url, content) Enregistre dans le cache le contenu HTML de la réponsedu serveur.

load_from_cache(url) Charge le contenu d’une URL correspondanteload_config() Permet de charger la configuration du filtrage d’un fichier texte de confi-guration