from http.server import BaseHTTPRequestHandler
import base64
from urllib.parse import parse_qs

class ConfigHandler(BaseHTTPRequestHandler):
    CONFIG_PATH = "/proxy-config"
    CONFIG_FILE = "proxy_config.txt" 
    def _load_config(self):
        config = {'mots_interdits': [], 'filtrage_actif': True}
        try:
            with open(self.CONFIG_FILE, 'r') as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if line.startswith('mots_interdits='):
                        mots = line.split('=', 1)[1].split('|')
                        config['mots_interdits'] = [m for m in mots if m]
                    elif line.startswith('filtrage_actif='):
                        config['filtrage_actif'] = line.split('=', 1)[1].lower() == 'true'
        except FileNotFoundError:
            pass
        return config
    
    def _save_config(self, config):
        with open(self.CONFIG_FILE, 'w') as f:
            f.write(f"mots_interdits={','.join(config['mots_interdits'])}\n")
            f.write(f"filtrage_actif={str(config['filtrage_actif']).lower()}\n")
    
    def _send_auth_required(self):
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="Proxy Admin"')
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b'Authentification requise')
    
    def do_GET(self):
        if self.path != self.CONFIG_PATH:
            self.send_error(404)
            return
            
        auth = self.headers.get('Authorization')
        if auth != 'Basic ' + base64.b64encode(b"admin:password").decode():
            self._send_auth_required()
            return
            
        config = self._load_config()
        
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = """\
<!DOCTYPE html>
<html>
<head>
    <title>Proxy Configuration</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .container {{ max-width: 800px; margin: 0 auto; }}
        textarea {{ width: 100%; height: 100px; }}
        .btn {{ padding: 8px 15px; background: #4CAF50; color: white; border: none; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Proxy Configuration</h1>
        <form method="POST">
            <h3>Mots interdits (un par ligne):</h3>
            <textarea name="mots_interdits">{mots}</textarea>
            
            <h3>Options:</h3>
            <label>
                <input type="checkbox" name="filtrage_actif" {checked}>
                Activer le filtrage
            </label>
            
            <br><br>
            <button type="submit" class="btn">Enregistrer</button>
        </form>
    </div>
</body>
</html>
""".format(
    mots="\n".join(config.get('mots_interdits', [])),
    checked='checked' if config.get('filtrage_actif', True) else ''
)
        self.wfile.write(html.encode('utf-8'))
    
    def do_POST(self):
        if self.path != self.CONFIG_PATH:
            self.send_error(404)
            return
            
        auth = self.headers.get('Authorization')
        if auth != 'Basic ' + base64.b64encode(b"admin:password").decode():
            self._send_auth_required()
            return
            
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')
        data = parse_qs(post_data)
        
        new_config = {
            'mots_interdits': [m.strip() for m in data.get('mots_interdits', [''])[0].split('\n') if m.strip()],
            'filtrage_actif': 'filtrage_actif' in data
        }
        
        self._save_config(new_config)
        
        self.send_response(303)
        self.send_header('Location', self.CONFIG_PATH)
        self.end_headers()