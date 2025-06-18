from datetime import datetime, timedelta
import json
import pickle
import re
import select
import os, sys, socket
import threading
from configHandler import ConfigHandler
import threading
from http.server import HTTPServer

#### CONFIGURATION DU CACHE
CACHE_FILE = "./cache/proxy_cache.txt"
cache = {}
CACHE_EXPIRATION = timedelta(minutes=30)

#### CONFIGURATION DU FILTRAGE - config handler
CONFIG_FILE = "proxy_config.txt"

#### CONFIGURATION DE LA SOCKET DU PROXY
numero_port = 8080
adresse_ip = ''
proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
proxy_socket.bind((adresse_ip, numero_port))
proxy_socket.listen(socket.SOMAXCONN)

# CODES COULEUR POUR LES PRINTS CONSOLES
class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    END = "\033[0m"

################ CACHES FONCTIONS ################ 
def save_to_cache(url, content):
    """Sauvegarde dans un fichier texte avec un fichier .meta"""
    safe_url = re.sub(r'[^a-zA-Z0-9]', '_', url)
    cache_path = os.path.join('cache', safe_url)
    
    # Fichier de contenu
    with open(cache_path, 'wb') as f:
        f.write(content)
    
    # Fichier meta (timestamp)
    with open(cache_path + '.meta', 'w') as f:
        f.write(str(datetime.now().timestamp()))

def load_from_cache(url):
    """Charge depuis le cache si valide"""
    safe_url = re.sub(r'[^a-zA-Z0-9]', '_', url)
    cache_path = os.path.join('cache', safe_url)
    meta_path = cache_path + '.meta'
    
    if not os.path.exists(meta_path):
        return None
    
    # Vérification expiration
    with open(meta_path, 'r') as f:
        timestamp = float(f.read())
    
    if datetime.now().timestamp() - timestamp > CACHE_EXPIRATION.total_seconds():
        os.remove(cache_path)
        os.remove(meta_path)
        return None
    
    with open(cache_path, 'rb') as f:
        return f.read()

##############Chargement configuration################
def load_config():
    config = {
        'mots_interdits': [],
        'filtrage_actif': True,
        'extensions_bloquees': []
    }
    
    try:
        with open('proxy_config.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                key, value = line.split('=', 1)
                key = key.strip().lower()
                
                if key == 'mots_interdits':
                    config['mots_interdits'] = [mot.strip() for mot in value.split(',')]
                elif key == 'filtrage_actif':
                    config['filtrage_actif'] = value.lower() in ('oui', 'yes', 'true', '1')
                elif key == 'extensions_bloquees':
                    config['extensions_bloquees'] = [ext.strip() for ext in value.split(',')]
    
    except FileNotFoundError:
        print("Fichier de configuration non trouvé, utilisation des valeurs par défaut")
    
    return config

##############Filtrage contenu HTML################
def filtrer_contenu_html(headers: str, body: bytes) -> (bytes, bytes):
    config = load_config()
    mots_interdits = config.get('mots_interdits', [])
    filtrage_actif = config.get('filtrage_actif', True)
    extensions_bloquees = config.get('extensions_bloquees', ['.mp4', '.exe', '.zip'])  # Nouvelle configuration

    print(f"\n{Colors.BOLD}{Colors.MAGENTA}=== DEBUG FILTRAGE ==={Colors.END}")
    print(f"{Colors.CYAN}Mots interdits:{Colors.END} {Colors.RED}{mots_interdits}{Colors.END}")
    print(f"{Colors.CYAN}Extensions bloquées:{Colors.END} {Colors.RED}{extensions_bloquees}{Colors.END}")
    print(f"{Colors.CYAN}Filtrage actif:{Colors.END} {Colors.GREEN if filtrage_actif else Colors.RED}{filtrage_actif}{Colors.END}")

    if not filtrage_actif:
        return headers.encode('utf-8'), body

    try:
        # Détection du Content-Type
        content_type = ""
        for line in headers.split('\n'):
            if line.lower().startswith('content-type:'):
                content_type = line.split(';')[0].lower()
                break

        # Décodage du corps
        try:
            body_str = body.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            body_str = body.decode('latin-1', errors='replace')

        # Filtrage des textes (HTML et texte brut)
        if 'text/html' in content_type or 'text/plain' in content_type:  # Modification pour texte brut
            # Filtrage du titre
            body_str = re.sub(r'<title>(.*?)</title>', r'<title>[FILTRÉ] \1</title>', body_str, flags=re.IGNORECASE)
            
            # Filtrage des mots interdits
            for mot in mots_interdits:
                body_str = re.sub(
                    re.escape(mot), 
                    '[CENSURÉ]', 
                    body_str, 
                    flags=re.IGNORECASE
                )

            # Blocage si contenu interdit
            if "interdit" in body_str.lower():
                nouveau_body = "<html><body><h1>Page bloquée par le proxy</h1></body></html>"
                nouveau_headers = f"HTTP/1.0 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {len(nouveau_body)}\r\n\r\n"
                return nouveau_headers.encode('utf-8'), nouveau_body.encode('utf-8')

        # Filtrage des extensions (pour tous les types de contenu)
        for ext in extensions_bloquees:
            if ext in content_type.lower() or f'href=".*{ext}' in body_str.lower():
                body_str = f"<html><body><h1>Contenu bloqué (extension {ext} interdite)</h1></body></html>"
                headers = f"HTTP/1.0 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {len(body_str)}\r\n\r\n"
                return headers.encode('utf-8'), body_str.encode('utf-8')

        # Filtrage spécifique HTML
        if 'text/html' in content_type:
            # Suppression des vidéos MP4 et autres médias
            body_str = re.sub(r'<(video|audio|embed)\b.*?</\1>', '', body_str, flags=re.DOTALL | re.IGNORECASE)
            body_str = re.sub(r'<source\b[^>]*(\.mp4|\.webm|\.ogg)[^>]*>', '', body_str, flags=re.IGNORECASE)

        return headers.encode('utf-8'), body_str.encode('utf-8')

    except Exception as e:
        print(f"{Colors.RED}Erreur dans le filtrage HTML:{Colors.END} {e}")
        return headers.encode('utf-8'), body


##################### Requete HTTPS #####################
# tunnel simple sans filtrage
def gere_requete_HTTPS(client_socket, requete):
    try:
        #----------Extractionhost:port----------
        print(f"{Colors.BOLD}{Colors.BLUE}=== TUNNEL HTTPS DEMARRE ==={Colors.END}")
        parts = requete.decode().split()
        if len(parts) < 2:
            raise ValueError("Requête CONNECT mal formée")
        
        host_port = parts[1].split(':')
        if len(host_port) != 2:
            raise ValueError("Format host:port invalide")
            
        host = host_port[0]
        try:
            port = int(host_port[1])
        except ValueError:
            raise ValueError("Le port doit être un nombre")
        #------------ connexion au serveur cible----------
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, port))
        # ------------ envoi d'une confirmation au client ----------
        client_socket.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        print(f"{Colors.GREEN}Tunnel établi: {host}:{port}{Colors.END}")
        # ----------- tunnel serveur<->client -------------
        sockets = [client_socket, server_socket]
        while True:
            readable, _, _ = select.select(sockets, [], [])
            for sock in readable:
                data = sock.recv(8192)
                if not data:
                    raise ConnectionError("Connexion fermée")  
                if sock is client_socket:
                    server_socket.send(data)
                else:
                    client_socket.send(data)
    except Exception as e:
        print(f"{Colors.RED}Erreur tunnel HTTPS: {type(e).__name__}: {e}{Colors.END}")
        try:
            client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except:
            pass
    finally:
        client_socket.close()
        if 'server_socket' in locals():
            server_socket.close()
        print(f"{Colors.BLUE}Tunnel HTTPS fermé{Colors.END}")


##################### Requete HTTP #####################
""" Fonction permettant de gérer une requette HTTP"""
def gere_requete_HTTP(client_socket, requete):
    try:
        ###PARTIE 1 : extraction URL et decomposition ####
        requete_str = requete.decode('utf-8', errors='replace') if isinstance(requete, bytes) else requete
        # ---------  methode, url et version --------- 
        lignes = requete_str.split('\r\n')
        premiere_ligne = lignes[0]
        try:
            methode, url, version = premiere_ligne.split()
        except ValueError:
            print("Requête malformée :", premiere_ligne)
            client_socket.close()
            return
        # ---------  headers --------- 
        headers = {}
        for ligne in lignes[1:]:
            if ':' in ligne:
                key, value = ligne.split(':', 1)
                headers[key.strip().lower()] = value.strip()
        # GESTION DE POST 
        body = b''
        if methode.upper() == 'POST' and 'content-length' in headers:
            content_length = int(headers['content-length'])
            while len(body) < content_length:
                data = client_socket.recv(4096)
                if not data:
                    break
                body += data
        # ---------  URL--------- 
        url = url.replace('http://', '').replace('https://', '')
        # ---------  port, chemin et host  --------- 
        port = 80
        if '/' in url:
            host, chemin = url.split('/', 1)
            chemin = '/' + chemin
        else:
            host = url
            chemin = '/'
            
        if ':' in host:
            host, port_str = host.split(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 80
        # VERIFICATION DU CACHE POUR GET
        if methode.upper() == 'GET' and url in cache:
            cached_data, timestamp = cache[url]
            if datetime.now() - timestamp < CACHE_EXPIRATION:
                print(f"[CACHE] Utilisation du cache pour {url}")
                client_socket.sendall(cached_data)
                return

        ### PARTIE 2: construction requete - envoie serveur - envoie client ### 
        requete_forward = [f"{methode} {chemin} HTTP/1.0"]  
        # ------------ suppression ligne ------------
        for key, value in headers.items():
            if key not in ['connection', 'proxy-connection', 'accept-encoding', 'content-length']:
                requete_forward.append(f"{key}: {value}")
        # ------------ Ajout du Host ------------
        if 'host' not in [h.split(':')[0].lower() for h in requete_forward[1:]]:
            requete_forward.append(f"Host: {host}")
        # ------------ reponse final à envoyer au serveur ----------  
        requete_forward.append("\r\n")
        requete_finale = '\r\n'.join(requete_forward).encode()
        
        ### PARTIE 3: initialisation de la socket du serveur cible ####
        try:
            serveur_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serveur_socket.connect((host, port))
            serveur_socket.sendall(requete_finale)
            if body:  # Envoi du corps POST si existe
                serveur_socket.sendall(body)
            # ------------ reception de la réponse de la part du serveur cible ------------
            reponse = b""
            while True:
                data = serveur_socket.recv(4096)
                if not data:
                    break
                reponse += data
            # ---------- Mise en cache (GET seulement) ---------- 
            if methode.upper() == 'GET' and b'200 OK' in reponse.split(b'\r\n\r\n')[0]:
                if b'\r\n\r\n' in reponse:
                    headers, body = reponse.split(b'\r\n\r\n',1)
                    headers_str = headers.decode('utf-8', errors='replace')
                    if 'text/html' in headers_str.lower():
                        headers, body = filtrer_contenu_html(headers_str, body)
                        reponse = headers + b'\r\n\r\n' + body
                print(f"[CACHE] Mise en cache (version filtrée) de {url}")
                cache[url] = (reponse, datetime.now())
                save_cache()
            # ------------ Filtrage du contenu ------------------
            if b'\r\n\r\n' in reponse:
                headers, body = reponse.split(b'\r\n\r\n', 1)
                headers_str = headers.decode('utf-8', errors='replace')
                if 'text/html' in headers_str.lower():
                    headers, body = filtrer_contenu_html(headers_str, body)
                reponse_finale = headers + b'\r\n\r\n' + body
            else:
                reponse_finale = reponse
            # ------------ Envoie de la réponse filtrer au client------------------
            client_socket.sendall(reponse_finale)

        # Erreurs et exceptions que deepseek m'a généré pour le déboggage du projet 
        except socket.gaierror:
            print(f"Erreur DNS: impossible de résoudre {host}")
            client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except ConnectionRefusedError:
            print(f"Connexion refusée par {host}:{port}")
            client_socket.send(b"HTTP/1.1 503 Service Unavailable\r\n\r\n")
        except Exception as e:
            print(f"Erreur de connexion: {e}")
            client_socket.send(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")

    except Exception as e:
        print(f"Erreur générale: {e}")
    finally:
        client_socket.close()
        if 'serveur_socket' in locals():
            serveur_socket.close()

##################### Analyse d'une requete #####################
def analyser_requete(requete_bytes):
    try:
        requete = requete_bytes.decode('utf-8')
    except UnicodeDecodeError:
        requete = requete_bytes.decode('latin-1')
    
    lignes = requete.split('\r\n')
    premiere_ligne = lignes[0]
    
    print("\nAnalyse détaillée:")
    print(f"Méthode: {premiere_ligne.split()[0]}")
    print(f"URL: {premiere_ligne.split()[1]}")
    print(f"Version HTTP: {premiere_ligne.split()[2]}")
    
    print("\nEn-têtes:")
    for header in lignes[1:]:
        if header:  
            print(f"- {header.split(':')[0]}: {':'.join(header.split(':')[1:]).strip()}")   

#####################Gere un client#####################           
def gerer_client(client_socket):
    requete = client_socket.recv(4096)
    if not requete : # pas de requeter
        return 
    
    if requete.startswith(b'CONNECT'): # HTTPS
        print("\n\033[1;35m=== REQUÊTE HTTPS RECUE ===\033[0m")
        analyser_requete(requete)
        gere_requete_HTTPS(client_socket, requete)
    else : # HTTP
        print("\n\033[1;36m=== REQUÊTE HTTP RECUE ===\033[0m")
        analyser_requete(requete)
        gere_requete_HTTP(client_socket, requete)
        
#####################Boucle principale#####################
while 1:
    (client_socket, TSAP_client) = proxy_socket.accept()
    print("Nouvelle connexion depuis ", TSAP_client)
    threading.Thread(target=gerer_client, args=(client_socket,)).start() # gérer client
