function main() {
    console.log(forge);
    pair = genKeyPair("prova");
    k = readKey(pair.privateKeyEnc, "prova");
    pair.privateKey = k;
    subject = '{ "COUNTRY_NAME": "IT", "STATE_OR_PROVINCE_NAME": "Italia", "LOCALITY_NAME": "Napoli", "ORGANIZATION_NAME": "MMV SPA",  "COMMON_NAME": "localhost", "DNSName": "localhost", "VALIDITY_DAYS": 365,  "EXTENSION": { "id": "mike", "role": "student" }}';
    subject = JSON.parse(subject);
    csr_pem = createCSR(subject, pair);
    challenge = 'pBsHuKCBNsEqc1F262o7RRut/7Goe+6Uxyy/i/KyuP/BHc0R/8ghlp9i5vlK/BxJEMRl5eVv1nDzGT/eJrZOiDcucgv1FvC1tIE5cXyoFb/Qxbvtva7ahOVaz7HwBp07omVMvCxwQBsS0J7bggjLIh8OTnLNgoVdhbTKNNNAiSiFpYEEfjL4u74huuwp3iw7bN5cGSk9hMkIpV6CYLRcszZe//P2hZur6Ey8LUqmDjf6Wwj3J0YAYuuof/gAlWi4lRpZYLqrXcb3IQSwwFQoa/13B/OsfvmT7ROV4qDAHNRuHWVrBN0gkEPeQ8iuXHccZFwdbI7plgl17MhUzxllMw==';
    challenge = atob(challenge);
    sig = makeSignature(pair.privateKey, challenge);
    verified = verifySignature(pair.publicKey, challenge, sig);
    status_msg1 = status();
    registration_msg = registration(csr_pem, subject);
    if (registration_msg.status == 200){
        cert = atob(registration_msg.cert);
        authenticate_msg = authenticate(cert);
        if (authenticate_msg.status == 200){
            status_msg2 = status();
            challenge_b64 = authenticate_msg.challenge;
            validate_challenge_msg = validate_challenge(pair.privateKey, challenge_b64);
            status_msg3 = status();
        }
    }
};