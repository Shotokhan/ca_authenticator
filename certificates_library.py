from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import datetime
import json
import ssl


def getSSLContext(cert_file, key_file, password):
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        cipher = 'AES256-GCM-SHA384'
        context.set_ciphers(cipher)
        context.load_cert_chain(cert_file, key_file, password)
        return context
    except ssl.SSLError:
        print("Invalid password in function getSSLContext")
        exit(1)


def genKeyPair(outfile, passphrase):
    # outfile is expected to be .pem
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # passphrase = input("Give me your passphrase\n>>>")
    with open(outfile, 'wb') as f:
        f.write(key.private_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PrivateFormat.TraditionalOpenSSL,
                                  encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode())))
    return key


def readKey(infile, passphrase):
    # passphrase = input("Give me your passphrase\n>>>")
    with open(infile, 'rb') as f:
        pem_data = f.read()
    try:
        key = serialization.load_pem_private_key(pem_data, passphrase.encode())
        return key
    except ValueError:
        print("Invalid password in function readKey")
        exit(1)


def readCAConfig(infile):
    # infile is expected to be .json
    with open(infile, 'r') as f:
        j = json.load(f)
    return j


def createCSR(subject_data, key, save_to_file=False, outfile=None):
    # outfile is expected to be .pem
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, subject_data['COUNTRY_NAME']),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_data['STATE_OR_PROVINCE_NAME']),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, subject_data['LOCALITY_NAME']),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_data['ORGANIZATION_NAME']),
                        x509.NameAttribute(NameOID.COMMON_NAME, subject_data['COMMON_NAME'])])
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject)
    # "1.2.840.113549.1.9.2" is UNSTRUCTURED_NAME extension; we use JSON as value
    ext = json.dumps(subject_data['EXTENSION']).encode()
    csr = csr.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.840.113549.1.9.2"), ext), critical=False)
    csr = csr.sign(key, hashes.SHA256())
    csr_serial = csr.public_bytes(serialization.Encoding.PEM)
    if save_to_file:
        with open(outfile, 'wb') as f:
            f.write(csr_serial)
    return csr, csr_serial


def signCertificateRequest(csr_cert, ca_cert, key, validity_days, save_to_file=False, outfile=None):
    # outfile is expected to be .pem
    cert = x509.CertificateBuilder().subject_name(csr_cert.subject)
    cert = cert.issuer_name(ca_cert.subject)
    cert = cert.public_key(csr_cert.public_key())
    cert = cert.serial_number(x509.random_serial_number())
    cert = cert.not_valid_before(datetime.datetime.utcnow())
    cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=validity_days))
    cert = cert.add_extension(csr.extensions[0].value, csr.extensions[0].critical)
    cert = cert.sign(key, hashes.SHA256())
    cert_serial = cert.public_bytes(serialization.Encoding.PEM)
    if save_to_file:
        with open(outfile, 'wb') as f:
            f.write(cert_serial)
    return cert, cert_serial


def createSelfSignedCert(outfile, ca_data, key):
    # outfile is expected to be .pem
    # ca_data is a dictionary; you can use a JSON to store it
    issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, ca_data['COUNTRY_NAME']),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ca_data['STATE_OR_PROVINCE_NAME']),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, ca_data['LOCALITY_NAME']),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_data['ORGANIZATION_NAME']),
                        x509.NameAttribute(NameOID.COMMON_NAME, ca_data['COMMON_NAME'])])
    subject = issuer
    cert = x509.CertificateBuilder()
    cert = cert.subject_name(subject)
    cert = cert.issuer_name(issuer)
    cert = cert.public_key(key.public_key())
    cert = cert.serial_number(x509.random_serial_number())
    cert = cert.not_valid_before(datetime.datetime.utcnow())
    cert = cert.not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=ca_data['VALIDITY_DAYS']))
    cert = cert.sign(key, hashes.SHA256())
    with open(outfile, 'wb') as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def readCertificate(infile):
    with open(infile, 'rb') as f:
        pem_data = f.read()
    cert = x509.load_pem_x509_certificate(pem_data)
    return cert


def verifyCertificate(ca_cert, cert_to_check):
    issuer_public_key = ca_cert.public_key()
    try:
        issuer_public_key.verify(cert_to_check.signature, cert_to_check.tbs_certificate_bytes, padding.PKCS1v15(), cert_to_check.signature_hash_algorithm)
        return True
    except InvalidSignature:
        return False


if __name__ == "__main__":
    k1 = genKeyPair('./test/ca_key.pem', 'prova')
    k2 = readKey('./test/ca_key.pem', 'prova')
    # print(k1.private_numbers().d)
    # print(k2.private_numbers().d)
    ca_data = readCAConfig("./volume/ca_data.json")
    c1 = createSelfSignedCert("./test/ca_cert.pem", ca_data, k2)
    c2 = readCertificate("./test/ca_cert.pem")
    # print(c1.serial_number)
    # print(c2.serial_number)
    # print(c1.subject)
    server_data = readCAConfig("./volume/server_data.json")
    new_k = genKeyPair('./test/server_key.pem', 'prova')
    csr, _ = createCSR(server_data, new_k)
    new_cert, _ = signCertificateRequest(csr, c2, k2, 7, save_to_file=True, outfile='./test/server_cert.pem')
    new_c2 = readCertificate('./test/server_cert.pem')
    verify = verifyCertificate(c2, new_c2)
    print(f"{verify = }")


