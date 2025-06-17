import select
import socket
import threading
import re
import os
from urllib.parse import urlparse

# Configuration
PROXY_PORT = 8080
CACHE_DIR = "cache"
BLOCKED_WORDS = ["blocked1", "blocked2"]  # Liste à charger depuis un fichier
BLOCKED_EXT = [".mp4", ".exe"]  # Extensions bloquées

# Initialisation du cache
if not os.path.exists(CACHE_DIR):
    os.makedirs(CACHE_DIR)

def save_to_cache(url, content):
    """Sauvegarde une réponse dans le cache"""
    filename = os.path.join(CACHE_DIR, re.sub(r"[^a-zA-Z0-9]", "_", url))
    with open(filename, "wb") as f:
        f.write(content)

def load_from_cache(url):
    """Charge une réponse depuis le cache"""
    filename = os.path.join(CACHE_DIR, re.sub(r"[^a-zA-Z0-9]", "_", url))
    if os.path.exists(filename):
        with open(filename, "rb") as f:
            return f.read()
    return None

def filter_content(content):
    """Filtre le contenu HTML (exemple : ajout d'un avertissement)"""
    if b"<title>" in content:
        content = content.replace(b"<title>", b"<title>[PROXIED] ")
    for word in BLOCKED_WORDS:
        content = content.replace(word.encode(), b"***CENSORED***")
    return content

def handle_http_request(client_socket, request):
    """Gère une requête HTTP normale (GET/POST)"""
    try:
        # Extraction de l'URL
        first_line = request.split(b"\r\n")[0].decode()
        method, url, version = first_line.split()
        
        # Vérification des extensions bloquées
        if any(url.endswith(ext) for ext in BLOCKED_EXT):
            client_socket.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked file type")
            return

        # Extraction des composants de l'URL
        parsed = urlparse(url)
        host = parsed.netloc
        path = parsed.path if parsed.path else "/"
        port = 80

        # Vérification du cache
        cached = load_from_cache(url)
        if cached:
            client_socket.send(filter_content(cached))
            return

        # Connexion au serveur cible
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, port))
        
        # Reconstruction de la requête
        modified_request = request.replace(
            f"{method} {url} HTTP/1.1".encode(),
            f"{method} {path} HTTP/1.0".encode()
        )
        server_socket.send(modified_request)

        # Réception et renvoi de la réponse
        response = b""
        while True:
            data = server_socket.recv(4096)
            if not data:
                break
            response += data

        # Filtrage et mise en cache
        filtered = filter_content(response)
        save_to_cache(url, filtered)
        client_socket.send(filtered)

    except Exception as e:
        print(f"HTTP Error: {e}")
        client_socket.send(b"HTTP/1.1 500 Internal Server Error\r\n\r\n")

def handle_https_request(client_socket, request):
    """Gère une requête HTTPS (CONNECT)"""
    try:
        # Extraction du host:port
        host_port = request.split()[1].decode()
        host, port = host_port.split(":")
        port = int(port)

        # Connexion au serveur cible
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((host, port))
        client_socket.send(b"HTTP/1.1 200 OK\r\n\r\n")

        # Relais bidirectionnel
        sockets = [client_socket, server_socket]
        while True:
            readable, _, _ = select.select(sockets, [], [])
            for sock in readable:
                data = sock.recv(4096)
                if not data:
                    return
                if sock is client_socket:
                    server_socket.send(data)
                else:
                    client_socket.send(data)

    except Exception as e:
        print(f"HTTPS Error: {e}")

def handle_client(client_socket):
    """Gère une connexion client"""
    request = client_socket.recv(4096)
    if not request:
        return

    if request.startswith(b"CONNECT"):
        handle_https_request(client_socket, request)
    else:
        handle_http_request(client_socket, request)

    client_socket.close()

def start_proxy():
    """Démarre le proxy"""
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind(("", PROXY_PORT))
    proxy_socket.listen(5)
    print(f"Proxy démarré sur le port {PROXY_PORT}")

    while True:
        client_socket, addr = proxy_socket.accept()
        print(f"Nouvelle connexion depuis {addr}")
        threading.Thread(target=handle_client, args=(client_socket,)).start()

if __name__ == "__main__":
    start_proxy()