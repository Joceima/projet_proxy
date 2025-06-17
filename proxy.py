import re
import os, sys, socket
import threading

numero_port = 8080
adresse_ip = ''
proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
proxy_socket.bind((adresse_ip, numero_port))
proxy_socket.listen(socket.SOMAXCONN)

def gere_requete_HTTPS(client_socket, requete):
    return

def filtrer_contenu_html(headers: str, body: bytes) -> (bytes, bytes):  # Retourne toujours des bytes
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
        mots_interdits = ['Bienvenue', 'adresse', 'disponibles', 'Site']
        for mot in mots_interdits:
            body_str = body_str.replace(mot, '[CENSURÉ]')

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
        ######### PARTIE 1 : extraction URL et décomposition ######### 
        premiere_ligne = requete_str.split('\n')[0]
        try:
            methode, url, version = premiere_ligne.split()
        except ValueError:
            print("Requête malformée :", premiere_ligne)
            client_socket.close()
            return  
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
        # Gestion du port personnalisé
        if ':' in host:
            host, port_str = host.split(':', 1)
            try:
                port = int(port_str)
            except ValueError:
                port = 80
        ######### PARTIE 2 : reconstruction de la requête #########
        # faire des requetes en version HTTP/1.0
        # suppression des lignes commançant par Keep-Alive et Proxy-Connection: Keep-Alive;
        # suppression de la ligne commançant par Accept-Encoding: gzip
        lignes = requete_str.split('\r\n')
        nouvelles_lignes = []
        for ligne in lignes:
            if (ligne.lower().startswith("connection:") or
                ligne.lower().startswith("proxy-connection:") or
                ligne.lower().startswith("accept-encoding:")):
                continue   
            elif ligne.startswith(methode):
                nouvelles_lignes.append(f"{methode} {chemin} HTTP/1.0")  
            elif ligne.strip():  
                nouvelles_lignes.append(ligne)
        # Reconstruction de la requête
        requete_reconstruit = '\r\n'.join(nouvelles_lignes) + '\r\n\r\n'
        ######### PARTIE 3 : envoi au serveur cible #########
        try:
            serveur_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            serveur_socket.connect((host, port))
            serveur_socket.sendall(requete_reconstruit.encode()) 
            # Réception de la réponse
            reponse = b""
            while True:
                data = serveur_socket.recv(4096)
                if not data:
                    break
                reponse += data  
            ######### PARTIE 4 : filtrage du contenu #########
            if b'\r\n\r\n' in reponse:
                headers, body = reponse.split(b'\r\n\r\n', 1)
                headers_str = headers.decode('utf-8', errors='replace')  
                if 'text/html' in headers_str.lower():
                    headers, body = filtrer_contenu_html(headers_str, body)    
                reponse_finale = headers + b'\r\n\r\n' + body
            else:
                reponse_finale = reponse  
            # envoie au client de la réponse finale
            client_socket.sendall(reponse_finale)
        # j'ai demandé à deepseek d'ajouter toutes les parties pour les exceptions et erreurs pour le déboggage
        except socket.gaierror:
            print(f"Erreur DNS avec host: {host}")
            client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception as e:
            print(f"Erreur de connexion au serveur: {e}")
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
        print("\n\033[1;35m=== REQUÊTE HTTPS RECUE ===\033[0m")
        gere_requete_HTTPS(client_socket, requete)
    else : # HTTP
        print("\n\033[1;36m=== REQUÊTE HTTP RECUE ===\033[0m")
        analyser_requete(requete)
        gere_requete_HTTP(client_socket, requete)
        

while 1:
    (client_socket, TSAP_client) = proxy_socket.accept()
    print("Nouvelle connexion depuis ", TSAP_client)
    threading.Thread(target=gerer_client, args=(client_socket,)).start()
