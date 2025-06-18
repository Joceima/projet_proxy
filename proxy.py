from datetime import datetime, timedelta
import json
import pickle
import re
import os, sys, socket
import threading
from configHandler import ConfigHandler
import threading
from http.server import HTTPServer

#### CONFIGURATION DU CACHE
CACHE_FILE = "./cache/proxy_cache.pkl"
cache = {}
CACHE_EXPIRATION = timedelta(minutes=30)

#### CONFIGURATION DU FILTRAGE - config handler
CONFIG_FILE = "proxy_config.json"

#### CONFIGURATION DE LA SOCKET DU PROXY
numero_port = 8080
adresse_ip = ''
proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
proxy_socket.bind((adresse_ip, numero_port))
proxy_socket.listen(socket.SOMAXCONN)

# CODES COULEUR 
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


def load_cache():
    try:
        with open(CACHE_FILE, 'rb') as f:
            return pickle.load(f)
    except (FileNotFoundError, EOFError):
        return {}

def save_cache():
    with open(CACHE_FILE, 'wb') as f:
        pickle.dump(cache, f)


# Chargement initial
cache = load_cache()

def gere_requete_HTTPS(client_socket, requete):
    return


def load_config():
    print("Chemin absolu du JSON:", os.path.abspath(CONFIG_FILE))
    try:
        with open(CONFIG_FILE) as f:
            config = json.load(f)
            # Nettoyage des mots interdits
            config['mots_interdits'] = [mot.strip() for mot in config['mots_interdits']]
            return config
    except (FileNotFoundError, json.JSONDecodeError):
        return {'mots_interdits': [], 'filtrage_actif': True}

def filtrer_contenu_html(headers: str, body: bytes) -> (bytes, bytes):  # Retourne toujours des bytes
    config = load_config()
    print(f"{Colors.CYAN}Configuration chargée:{Colors.END} {config}")
    mots_interdits = config.get('mots_interdits', [])
    filtrage_actif = config.get('filtrage_actif', True)
    
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}=== DEBUG FILTRAGE ==={Colors.END}")
    print(f"{Colors.CYAN}Mots interdits:{Colors.END} {Colors.RED}{mots_interdits}{Colors.END}")
    print(f"{Colors.CYAN}Filtrage actif:{Colors.END} {Colors.GREEN if filtrage_actif else Colors.RED}{filtrage_actif}{Colors.END}")

    if not filtrage_actif:
        return headers.encode('utf-8'), body

    try:
        content_type = ""
        for line in headers.split('\n'):
            if line.lower().startswith('content-type:'):
                content_type = line.split(';')[0].lower()
                break

        if 'text/html' not in content_type:
            return headers.encode('utf-8'), body  #
        try:
            body_str = body.decode('utf-8', errors='replace')
        except UnicodeDecodeError:
            body_str = body.decode('latin-1', errors='replace')

        # Filtrage du contenu
        body_str = re.sub(r'<title>(.*?)</title>', r'<title>[FILTRÉ] \1</title>', body_str, flags=re.IGNORECASE)
        #mots_interdits = ['Bienvenue', 'adresse', 'disponibles', 'Site']
        for mot in mots_interdits:
            #body_str = body_str.replace(mot, '[CENSURÉ]')
            body_str = re.sub(re.escape(mot), '[CENSURÉ]', body_str, flags=re.IGNORECASE )

        if "interdit" in body_str.lower():
            nouveau_body = "<html><body><h1>Page bloquée par le proxy</h1></body></html>"
            nouveau_headers = "HTTP/1.0 403 Forbidden\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n".format(len(nouveau_body))
            return nouveau_headers.encode('utf-8'), nouveau_body.encode('utf-8')  # Les deux en bytes

        # Suppression des vidéos MP4
        body_str = re.sub(r'<video\b.*?</video>', '', body_str, flags=re.DOTALL | re.IGNORECASE)
        body_str = re.sub(r'<source\b[^>]*\.mp4[^>]*>', '', body_str, flags=re.IGNORECASE)

        return headers.encode('utf-8'), body_str.encode('utf-8')  # Les deux en bytes

    except Exception as e:
        print("Erreur dans le filtrage HTML:", e)
        return headers.encode('utf-8'), body  # Headers en bytes

def enregistre_dans_cache(donnees_censurees):
    return

""" Fonction permettant de gérer une requette HTTP"""
def gere_requete_HTTP(client_socket, requete):
    try:
        # Décodage de la requête
        requete_str = requete.decode('utf-8', errors='replace') if isinstance(requete, bytes) else requete
        
        # Extraction des informations de base
        lignes = requete_str.split('\r\n')
        premiere_ligne = lignes[0]
        try:
            methode, url, version = premiere_ligne.split()
        except ValueError:
            print("Requête malformée :", premiere_ligne)
            client_socket.close()
            return

        # Extraction des headers
        headers = {}
        for ligne in lignes[1:]:
            if ':' in ligne:
                key, value = ligne.split(':', 1)
                headers[key.strip().lower()] = value.strip()

        # Gestion du corps POST
        body = b''
        if methode.upper() == 'POST' and 'content-length' in headers:
            content_length = int(headers['content-length'])
            while len(body) < content_length:
                data = client_socket.recv(4096)
                if not data:
                    break
                body += data

        # Nettoyage URL
        url = url.replace('http://', '').replace('https://', '')
        
        # Extraction host/port/chemin
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

        # Vérification du cache (GET seulement)
        if methode.upper() == 'GET' and url in cache:
            cached_data, timestamp = cache[url]
            if datetime.now() - timestamp < CACHE_EXPIRATION:
                print(f"[CACHE] Utilisation du cache pour {url}")
                client_socket.sendall(cached_data)
                return

        # Reconstruction de la requête
        requete_forward = [f"{methode} {chemin} HTTP/1.0"]  # Force HTTP/1.0
        
        # Conservation des headers importants
        for key, value in headers.items():
            if key not in ['connection', 'proxy-connection', 'accept-encoding', 'content-length']:
                requete_forward.append(f"{key}: {value}")
        
        # Ajout du Host si manquant
        if 'host' not in [h.split(':')[0].lower() for h in requete_forward[1:]]:
            requete_forward.append(f"Host: {host}")
            
        requete_forward.append("\r\n")
        requete_finale = '\r\n'.join(requete_forward).encode()
        
        # Connexion au serveur
        try:
            serveur_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serveur_socket.connect((host, port))
            
            # Envoi de la requête
            serveur_socket.sendall(requete_finale)
            if body:  # Envoi du corps POST si existe
                serveur_socket.sendall(body)

            # Réception de la réponse
            reponse = b""
            while True:
                data = serveur_socket.recv(4096)
                if not data:
                    break
                reponse += data

            # Mise en cache (GET seulement)
            if methode.upper() == 'GET' and b'200 OK' in reponse.split(b'\r\n')[0]:
                print(f"[CACHE] Mise en cache de {url}")
                cache[url] = (reponse, datetime.now())
                save_cache()

            # Filtrage du contenu
            if b'\r\n\r\n' in reponse:
                headers, body = reponse.split(b'\r\n\r\n', 1)
                headers_str = headers.decode('utf-8', errors='replace')
                if 'text/html' in headers_str.lower():
                    headers, body = filtrer_contenu_html(headers_str, body)
                reponse_finale = headers + b'\r\n\r\n' + body
            else:
                reponse_finale = reponse

            client_socket.sendall(reponse_finale)

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
            
def gerer_client(client_socket):
    requete = client_socket.recv(4096)
    if not requete : # pas de requeter
        return 
    
    if requete.startswith(b'CONNECT'): # HTTPS
        #print("\n\033[1;35m=== REQUÊTE HTTPS RECUE ===\033[0m")
        gere_requete_HTTPS(client_socket, requete)
    else : # HTTP
        print("\n\033[1;36m=== REQUÊTE HTTP RECUE ===\033[0m")
        analyser_requete(requete)
        gere_requete_HTTP(client_socket, requete)
        

while 1:
    (client_socket, TSAP_client) = proxy_socket.accept()
    print("Nouvelle connexion depuis ", TSAP_client)
    threading.Thread(target=gerer_client, args=(client_socket,)).start() # gérer client
