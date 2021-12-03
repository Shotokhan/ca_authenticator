function genKeyPair(passphrase) {
    rsa = forge.pki.rsa;
    pki = forge.pki;
    // 2048 bits key generation can require some time
    k = rsa.generateKeyPair({bits: 1024, e: 0x10001});
    ser = pki.privateKeyToPem(k.privateKey);
    // ser = JSON.stringify(k); // misses prototype info
    enc = encrypt(ser, passphrase);
    pair = { publicKey: k.publicKey, privateKeyEnc: enc }
    return pair;
}


function readKey(encKey, passphrase) {
    pki = forge.pki;
    result = decrypt(encKey, passphrase);
    if (result['check'] == false) {
        throw new Error("Invalid password")
    } else {
        ser = result['plaintext'];
        k = pki.privateKeyFromPem(ser);
        // k = JSON.parse(ser);
        return k;
    }
}


function encrypt(input, password) {
    // AES-128-CBC
    var keySize = 16;
    var ivSize = 16;

    // get derived bytes
    // Notes:
    // 1. If using an alternative hash (eg: "-md sha1") pass
    //   "forge.md.sha1.create()" as the final parameter.
    // 2. If using "-nosalt", set salt to null.
    var salt = forge.random.getBytesSync(8);
    // var md = forge.md.sha1.create(); // "-md sha1"
    var derivedBytes = forge.pbe.opensslDeriveBytes(
        password, salt, keySize + ivSize, forge.md.sha256.create());
    var buffer = forge.util.createBuffer(derivedBytes);
    var key = buffer.getBytes(keySize);
    var iv = buffer.getBytes(ivSize);

    var cipher = forge.cipher.createCipher('AES-CBC', key);
    cipher.start({iv: iv});
    cipher.update(forge.util.createBuffer(input, 'binary'));
    cipher.finish();

    var output = forge.util.createBuffer();

    // if using a salt, prepend this to the output:
    if(salt !== null) {
        output.putBytes('Salted__'); // (add to match openssl tool output)
        output.putBytes(salt);
    }
    output.putBuffer(cipher.output);

    return output.getBytes();
}


function decrypt(input, password) {
    // parse salt from input
    input = forge.util.createBuffer(input, 'binary');
    // skip "Salted__" (if known to be present)
    input.getBytes('Salted__'.length);
    // read 8-byte salt
    var salt = input.getBytes(8);

    // Note: if using "-nosalt", skip above parsing and use
    // var salt = null;

    // AES-128 key and IV sizes
    var keySize = 16;
    var ivSize = 16;

    var derivedBytes = forge.pbe.opensslDeriveBytes(
        password, salt, keySize + ivSize, forge.md.sha256.create());
    var buffer = forge.util.createBuffer(derivedBytes);
    var key = buffer.getBytes(keySize);
    var iv = buffer.getBytes(ivSize);

    var decipher = forge.cipher.createDecipher('AES-CBC', key);
    decipher.start({iv: iv});
    decipher.update(input);
    var result = decipher.finish(); // check 'result' for true/false

    return { plaintext: decipher.output, check: result };
}


function subjectToAttrs(subject) {

    //var subject = JSON.parse(subject);
    var attrs = [{
            name: 'countryName',
            value: subject.COUNTRY_NAME
        }, {
            name: 'stateOrProvinceName',
            value: subject.STATE_OR_PROVINCE_NAME
        }, {
            name: 'localityName',
            value: subject.LOCALITY_NAME
        }, {
            name: 'organizationName',
            value: subject.ORGANIZATION_NAME
        }, {
            name: 'commonName',
            // value: subject.COMMON_NAME
            value: JSON.stringify(subject.EXTENSION)
        }
    ];

    return attrs;

}


function createCSR(subject, pair) {
    // subject is a dictionary
    var pki = forge.pki;
    var csr = forge.pki.createCertificationRequest();
    var attrs = subjectToAttrs(subject);
    csr.publicKey = pair.publicKey;
    csr.setSubject(attrs);
    // unrecognizedExtension doesn't work in forge library; nsComment is okay but can't use more than 128 chars
    // see: https://github.com/digitalbazaar/forge/blob/c0bb359afca73bb0f3ba6feb3f93bbcb9166af2e/lib/x509.js#L2091
    // it still doesn't work after serialization; so we use common name for extension
    // csr.setAttributes([{ name: 'extensionRequest', extensions: { name: 'nsComment', value: JSON.stringify(subject.EXTENSION) } }]);
    csr.sign(pair.privateKey);
    var csr_pem = pki.certificationRequestToPem(csr);

    return csr_pem;
}


function loadCertificate(pem_data) {
    var pki = forge.pki;
    cert = pki.certificateFromPem(pem_data);
    return cert;
}


function makeSignature(privateKey, challenge) {
    var md = forge.md.sha256.create();
    md.update(challenge, 'binary');
    var signature = privateKey.sign(md);
    return signature;
}


function verifySignature(publicKey, challenge, signature) {
    var md = forge.md.sha256.create();
    md.update(challenge, 'binary');
    var verified = publicKey.verify(md.digest().bytes(), signature);
    return verified;
}
