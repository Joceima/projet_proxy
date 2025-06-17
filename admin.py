from http.server import HTTPServer
from configHandler import ConfigHandler
import webbrowser
import threading

def run_admin_interface():
    server_address = ('localhost', 8081)
    httpd = HTTPServer(server_address, ConfigHandler)
    print(f"Admin interface running on http://{server_address[0]}:{server_address[1]}/proxy-config")
    print("Username: admin | Password: password")
    webbrowser.open(f"http://{server_address[0]}:{server_address[1]}/proxy-config")
    httpd.serve_forever()

if __name__ == '__main__':
    run_admin_interface()