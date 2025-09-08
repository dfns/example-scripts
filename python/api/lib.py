#!/usr/bin/python

import ecdsa
from ecdsa.util import sigencode_der, sigdecode_der
from hashlib import sha256

def ecdsa_sign(privateKeyPem, message):
    privateKey = ecdsa.SigningKey.from_pem(privateKeyPem)
    return privateKey.sign_deterministic(message, hashfunc=sha256, sigencode=sigencode_der)

def ecdsa_verify(publicKeyPem, message, signature):
    isValid = True
    publicKey = ecdsa.VerifyingKey.from_pem(publicKeyPem)
    try:
        publicKey.verify(signature, message, hashfunc=sha256, sigdecode=sigdecode_der)
    except ecdsa.BadSignatureError:
        isValid = False
    return isValid

