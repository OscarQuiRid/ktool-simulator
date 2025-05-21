import os
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509 import NameOID
from cryptography import x509
from datetime import datetime, timedelta

def crear_par_claves(archivo_clave_publica, archivo_keystore, archivo_store_meta, clave_password, store_password):
    clave_privada = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    clave_publica = clave_privada.public_key()

    with open(archivo_keystore, "wb") as f:
        f.write(clave_privada.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(clave_password.encode())
        ))

    with open(archivo_clave_publica, "wb") as f:
        f.write(clave_publica.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    with open(archivo_store_meta, "wb") as f:
        contenido = f"Archivo seguro para validar acceso a {os.path.basename(archivo_keystore)}".encode()
        dummy_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        f.write(dummy_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(store_password.encode())
        ))

    print("✅ Claves generadas y almacén creado.")

def crear_csr(identificador, archivo_keystore, archivo_csr, clave_password):
    with open(archivo_keystore, "rb") as f:
        clave_privada = serialization.load_pem_private_key(
            f.read(),
            password=clave_password.encode(),
        )

    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Catalonia"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Montmeló"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"MyCompany"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"MyCompany.cat"),
    ])).sign(clave_privada, hashes.SHA256())

    with open(archivo_csr, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    print(f"📜 CSR creado en {archivo_csr}")

def main():
    dir_claves = os.path.join(os.path.dirname(__file__), 'Keys')
    dir_clave_publica = os.path.join(os.path.dirname(__file__), 'PublicKey')
    dir_certificados = os.path.join(os.path.dirname(__file__), 'Certificate')

    os.makedirs(dir_claves, exist_ok=True)
    os.makedirs(dir_clave_publica, exist_ok=True)
    os.makedirs(dir_certificados, exist_ok=True)

    print("Introduce tu nombre:")
    nombre = input().strip()
    print("Introduce tu apellido:")
    apellido = input().strip()
    print("Introduce una contraseña para proteger la clave privada:")
    clave_password = input().strip()
    print("Introduce una contraseña para acceder al almacén:")
    store_password = input().strip()

    identificador = (nombre[:3] + apellido[:3]).lower()
    archivo_keystore = os.path.join(dir_claves, f"{identificador}_keystore.pem")
    archivo_csr = os.path.join(dir_certificados, f"{identificador}_csr.pem")
    archivo_clave_publica = os.path.join(dir_clave_publica, f"{identificador}_public.pem")
    archivo_store_meta = os.path.join(dir_claves, f"{identificador}_storemeta.pem")

    crear_par_claves(archivo_clave_publica, archivo_keystore, archivo_store_meta, clave_password, store_password)
    crear_csr(identificador, archivo_keystore, archivo_csr, clave_password)

if __name__ == "__main__":
    main()