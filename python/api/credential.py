import os
import base64
import json
import lib
from abc import ABC, abstractmethod
from hashlib import sha256

class Credential(ABC):

    def __init__(self, credId = ''):
        self.credentialInfo = {}
        self.credentialAssertion = {}
        self.clientData = {}
        self.clientDataJson = b''
        self.clientDataJsonB64 = ''
        self.attestationData = {}
        self.attestationDataJson = b''
        self.attestationDataJsonB64 = ''
        self.credId = ''
        self._setCredId(credId)
        self.assertionSignature = b''
        self.assertionSignatureB64 = ''
        # FIDO2 specific (not implemented)
        self.authenticatorDataB64 = ''
        self.userHandle = ''
         
    def _setCredId(self, credId):
        if credId != '':
            self.credId = credId
        else:
            random_bytes = os.urandom(32)
            self.credId = base64.urlsafe_b64encode(random_bytes).decode('utf-8')

    def _jsondumps(self, obj):
        # This is important for compatibility with the backend
        return json.dumps(obj, separators=(',', ':'), sort_keys=True).encode('utf-8')

    def _setCredentialInfo(self):
        credentialInfo = {}
        credentialInfo["credId"] = self.credId
        credentialInfo["clientData"] = self.clientDataJsonB64
        credentialInfo["attestationData"] = self.attestationDataJsonB64
        self.credentialInfo = credentialInfo

    def _setCredentialAssertion(self):
        credentialAssertion = {}
        credentialAssertion["credId"] = self.credId
        credentialAssertion["clientData"] = self.clientDataJsonB64
        credentialAssertion["signature"] = self.assertionSignatureB64
        # FIDO2 specific (not implemented)
        if self.userHandle != '':
            credentialAssertion["userHandle"] = self.userHandle
        if self.authenticatorDataB64 != '':
            credentialAssertion["authenticatorData"] = self.authenticatorDataB64
        self.credentialAssertion = credentialAssertion

    def getInfo(self):
        self._setCredentialInfo()
        return self.credentialInfo

    def getAssertion(self):
        self._setCredentialAssertion()
        return self.credentialAssertion

    def getCredId(self):
        return self.credId

    @abstractmethod
    def _setClientData(self):
        pass

    @abstractmethod
    def _setAttestationData(self):
        pass

    @abstractmethod
    def _setAssertionSignature(self):
        pass


class KeyCredential(Credential):
    """Key Credential
    https://docs.dfns.co/d/api-docs/authentication/registration/completeuserregistration#key-credential
    """

    def __init__(self, publicKey, privateKey, origin, crossOrigin, challenge, credId = '', create = True):
        super().__init__(credId)
        self.publicKeyPem = publicKey
        self.privateKeyPem = privateKey
        self.origin = origin
        self.crossOrigin = crossOrigin
        self.challenge = challenge
        self._setClientData(create)
        self._setAttestationData()
        self._setAssertionSignature()

    def _setClientData(self, create):
        """Client Data Format
        https://docs.dfns.co/d/advanced-topics/authentication/request-signing#client-data-format
        """
        clientData = {}
        if create:
            clientData["type"] = "key.create"
        else:
            clientData["type"] = "key.get"
        clientData["challenge"] = self.challenge
        clientData["origin"] = self.origin
        clientData["crossOrigin"] = False
        self.clientData = clientData
        self.clientDataJson = self._jsondumps(self.clientData)
        self.clientDataJsonB64 = base64.urlsafe_b64encode(self.clientDataJson).decode('utf-8')

    def _setAttestationData(self):
        """Credential Assertion
        https://docs.dfns.co/d/advanced-topics/authentication/credentials/user-credentials#credential-assertion
        """
        attestationData = {}
        attestationData["publicKey"] = self.publicKeyPem
        clientDataJsonHash = sha256(self.clientDataJson).digest().hex()
        toSign = {"clientDataHash": clientDataJsonHash, "publicKey": self.publicKeyPem}
        toSignJson = self._jsondumps(toSign)
        signature = lib.ecdsa_sign(self.privateKeyPem, toSignJson)
        attestationData["signature"] = signature.hex()
        self.attestationData = attestationData
        self.attestationDataJson = self._jsondumps(self.attestationData)
        self.attestationDataJsonB64 = base64.urlsafe_b64encode(self.attestationDataJson).decode('utf-8')

    def _setAssertionSignature(self):
        toSignJson = self.clientDataJson
        signature = lib.ecdsa_sign(self.privateKeyPem, toSignJson)
        self.assertionSignature = signature
        self.assertionSignatureB64 = base64.urlsafe_b64encode(signature).decode('utf-8')