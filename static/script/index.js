function main() {
    console.log(forge);
    pair = genKeyPair("prova");
    k = readKey(pair.privateKeyEnc, "prova");
    pair.privateKey = k;
    subject = '{ "COUNTRY_NAME": "IT", "STATE_OR_PROVINCE_NAME": "Italia", "LOCALITY_NAME": "Napoli", "ORGANIZATION_NAME": "MMV SPA",  "COMMON_NAME": "localhost", "DNSName": "localhost", "VALIDITY_DAYS": 365,  "EXTENSION": { "id": "mike", "role": "student" }}';
    subject = JSON.parse(subject);
    csr = createCSR(subject, pair);
    challenge = 'pBsHuKCBNsEqc1F262o7RRut/7Goe+6Uxyy/i/KyuP/BHc0R/8ghlp9i5vlK/BxJEMRl5eVv1nDzGT/eJrZOiDcucgv1FvC1tIE5cXyoFb/Qxbvtva7ahOVaz7HwBp07omVMvCxwQBsS0J7bggjLIh8OTnLNgoVdhbTKNNNAiSiFpYEEfjL4u74huuwp3iw7bN5cGSk9hMkIpV6CYLRcszZe//P2hZur6Ey8LUqmDjf6Wwj3J0YAYuuof/gAlWi4lRpZYLqrXcb3IQSwwFQoa/13B/OsfvmT7ROV4qDAHNRuHWVrBN0gkEPeQ8iuXHccZFwdbI7plgl17MhUzxllMw==';
    challenge = atob(challenge);
    sig = makeSignature(pair.privateKey, challenge);
    verified = verifySignature(pair.publicKey, challenge, sig);
    status_msg = status('https://localhost:5001');
};