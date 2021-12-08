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
    # TODO: self-verify cert_file
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


def readConfigFromJSON(infile):
    # infile is expected to be .json
    with open(infile, 'r') as f:
        j = json.load(f)
    return j


def serializeCert(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


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
    csr_serial = serializeCert(csr)
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
    try:
        cert = cert.add_extension(csr_cert.extensions[0].value, csr_cert.extensions[0].critical)
    except IndexError:
        ext = csr_cert.subject.rfc4514_string()
        ext = ext.split('=')
        ext = ext[ext.index('CN')+1].split('},')[0].encode() + b'}'
        cert = cert.add_extension(x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.840.113549.1.9.2"), ext), critical=False)
    cert = cert.sign(key, hashes.SHA256())
    cert_serial = serializeCert(cert)
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
        f.write(serializeCert(cert))
    return cert


def readCertificate(infile):
    with open(infile, 'rb') as f:
        pem_data = f.read()
    cert = loadCertificate(pem_data)
    return cert


def loadCertificate(pem_data):
    cert = x509.load_pem_x509_certificate(pem_data)
    return cert


def loadCSR(pem_data):
    # CSR is an authenticated request, so it doesn't require challenge/response after
    csr = x509.load_pem_x509_csr(pem_data)
    assert csr.is_signature_valid, "CSR signature is not valid"
    return csr


def verifySignature(pk, signature, data, hash_alg, padding_alg=None):
    # only works for RSA
    if padding_alg is None:
        padding_alg = padding.PKCS1v15()
    try:
        pk.verify(signature, data, padding_alg, hash_alg)
        return True
    except InvalidSignature:
        return False


def makeSignature(key, data, hash_alg, padding_alg=None):
    if padding_alg is None:
        padding_alg = padding.PKCS1v15()
    return key.sign(data, padding_alg, hash_alg)


def verifyCertificate(ca_cert, cert_to_check):
    # TODO: verify chain, verify CRL (is CRL a parameter to this function?)
    issuer_public_key = ca_cert.public_key()
    check = verifySignature(issuer_public_key, cert_to_check.signature, cert_to_check.tbs_certificate_bytes, cert_to_check.signature_hash_algorithm)
    check &= verifyTimeValidity(cert_to_check)
    check &= verifyCertChain(ca_cert, cert_to_check)
    check &= verifyRevocation(ca_cert, cert_to_check, crl=None)
    return check


def verifyCertChain(ca_cert, cert_to_check):
    # stub
    return True


def verifyRevocation(ca_cert, cert_to_check, crl):
    # stub
    return True


def verifyTimeValidity(cert_to_check):
    expiration = cert_to_check.not_valid_after.timestamp()
    return datetime.datetime.now().timestamp() < expiration


if __name__ == "__main__":
    debug = False
    CAPass = input('Password for encrypting CA private key\n> ').strip()
    ca_key_file = './test/ca_key.pem'
    k1 = genKeyPair(ca_key_file, CAPass)
    print(f"Encrypted CA private key written to {ca_key_file}")
    k2 = readKey(ca_key_file, CAPass)
    if debug:
        print("RSA private key's d")
        print(k2.private_numbers().d, end='\n\n')
    ca_data = readConfigFromJSON("./volume/ca_data.json")
    ca_cert_file = "./test/ca_cert.pem"
    c1 = createSelfSignedCert(ca_cert_file, ca_data, k2)
    print(f"CA Certificate written to {ca_cert_file}")
    c2 = readCertificate(ca_cert_file)
    if debug:
        print("Self signed certificate's serial number")
        print(c2.serial_number, end='\n\n')
        print("Self signed certificate's subject")
        print(c2.subject, end='\n\n')
    server_data = readConfigFromJSON("./volume/server_data.json")
    serverPass = input('Password for encrypting server private key\n> ').strip()
    server_key_file = './test/server_key.pem'
    new_k = genKeyPair(server_key_file, serverPass)
    print(f"Encrypted server private key written to {server_key_file}")
    csr, _ = createCSR(server_data, new_k)
    if debug:
        print("CSR's extension")
        print(csr.extensions[0].value, end='\n\n')
    validity_days = int(input('Validity days for server certificate\n> ').strip())
    server_cert_file = './test/server_cert.pem'
    new_cert, _ = signCertificateRequest(csr, c2, k2, validity_days, save_to_file=True, outfile=server_cert_file)
    print(f"Server Certificate written to {server_cert_file}")
    new_c2 = readCertificate(server_cert_file)
    verify = verifyCertificate(c2, new_c2)
    if debug:
        print("Verify of the certificate signed by the CA")
        print(f"{verify = }", end='\n\n')
