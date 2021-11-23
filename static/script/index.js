function main(){
    console.log(forge);
    enc = genKeyPair("prova");
    k = readKey(enc, "prova");
}; 


function genKeyPair(passphrase) {
    rsa = forge.pki.rsa;
    pki = forge.pki;
    // 2048 bits key generation can require some time
    k = rsa.generateKeyPair({bits: 1024, e: 0x10001});
    // ser = pki.privateKeyToPem(k.privateKey); // throws errors after decryption
    ser = JSON.stringify(k);
    enc = encrypt(ser, passphrase);
    return enc;
}


function readKey(encKey, passphrase) {
    pki = forge.pki;
    result = decrypt(encKey, passphrase);
    if (result['check'] == false) {
        throw new Error("Invalid password")
    } else {
        ser = result['plaintext'];
        // k = pki.privateKeyFromPem(ser); // throws errors after decryption
        k = JSON.parse(ser);
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

    return {plaintext: decipher.output, check: result}
}
