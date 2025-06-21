from OpenSSL import crypto, SSL
import random
import os

# https://www.pyopenssl.org/en/latest/introduction.html

class MITMPProxy:
    def __init__(self, ca_key_path = 'ca_key.pem', ca_cert_path = 'ca.crt'):
        print("On est dans la fonction init de MITMPProxy")
        self.ca_key_path = ca_key_path
        self.ca_cert_path = ca_cert_path
        print("Initialisation des paths; maintenant on va generer ca_key et ca_cert")
        if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
            print("On est dans la condiion")
            print("Genere ROOT CA")
            self.ca_key, self.ca_cert = self.genere_root_ca("MITM Proxy Root CA")
        else:
            print("On est dans le sinon où on charge les clés")
            self.ca_key = self.__load_key__(ca_key_path)
            self.ca_cert = self.__load_cert__(ca_cert_path)

    """
    crée une autorité de certification racine
    Durée de vie longue
    auto-signée
    permet de signer d'autres certificats
    """
    def genere_root_ca(self, common_name): # retourne key et cert
        print("On est dans le fonction genere_root_ca")
        # class OpenSSL.crypto.PKey
        # représente une DSA ou RSA public key or key pair
        key = crypto.PKey()
        # génre une kay pair d'un type donnée, ICI type RSA avec un nombre de bit donné
        key.generate_key(crypto.TYPE_RSA, 4096)

        # class OpenSSL.crypto.X509
        # réprésente X.509 certificat
        cert = crypto.X509()
        # set the versio number of the certicate
        cert.set_version(2)
        # set the serial numer of the certificate 
        cert.set_serial_number(random.randint(50000000, 100000000))

        print("Subject du certificat")

        # set subject of this certificate
        subject = self.ca_cert.get_subject()
        subject.CN = common_name
        subject.O = "MITM Proxy"
        subject.C = "FR"

        #set the timestamp at which the certificate starts being valid
        cert.gmtime_adj_notBefore(0)
        # set the timestamp at which the certificate stops beoing valie 
        cert.gmtime_adj_notAfter(365*24*60*60)

        # set the issuer of this certificate 
        cert.set_issuer(subject)
        # set the public key of this certificate
        cert.set_pubkey(key)

        # set extension 
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
            crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        ])
        # sign the certificate signing request with this key and digest type 
        cert.sign(key, 'sha256')

        with open(self.ca_key_path, 'wb') as f:
            print("Ecriture dans le fichier ca_key.pem")
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        with open(self.ca_cert_path, 'wb') as f:
            print("Ecriture dans le fichier ca.crt")
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        return key, cert
    
    """
    génère un certificat pour le domaine 
    Inclut le SAN (subject alternative name)
    signé par le CA racine
    durée de vie 1 an
    """
    def genere_CERT(self, hostname):
        print("On est dans le fonction genere_Cert")
        print(f"self.ca_cert: {self.ca_cert}")
        print(f"self.ca_key :{self.ca_key}")
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        cert = crypto.X509()
        cert.set_version(2)
        cert.set_serial_number(random.randint(10**6, 10**7))
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(365*24*60*60)

        #cert.get_subject().CN = hostname

        print("Get subject")
        subject = cert.get_subject()
        subject.CN = hostname
        cert.set_issuer(subject)

        print("fin du subject")
        cert.set_pubkey(key)

        print("début ajout des extensions")
        cert.add_extensions([
            crypto.X509Extension(b"subjectAltName", False,
                                 f"DNS:{hostname}".encode()),
                                 crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
                                 crypto.X509Extension(b"keyUsage", False, b"digitalSignature, keyEncipherment"),
                                 crypto.X509Extension(b"extendedKeyUsage", False, b"serverAuth")
        ])

        print("fin ajout extension")
        
        cert.sign(self.ca_key, 'sha256')
        print("signature")

        # encrypt into PEM format
        return (
            # dump the private key pkey into a buffer string encoded with the type type 
            crypto.dump_privatekey(crypto.FILETYPE_PEM, key),
            # dump the certificate cert into a buffer string encoded with the type type 
            crypto.dump_certificate(crypto.FILETYPE_PEM, cert),
            crypto.dump_certificate(crypto.FILETYPE_PEM, self.ca_cert)
        )

    """
    charge une clé privé PEM
    nécessaire pour signer
    """
    def __load_key__(self,path_key):
        with open(path_key, "rb") as f:
            ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
        return ca_key
    
    """
    charge un certificat X509
    """
    def __load_cert__(self,path_crt):
        with open(path_crt, "rb") as f:
            ca_crt = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
     