import base64
from credential import KeyCredential
from dfnsApi import DfnsAPI

class Login:

    def __init__(self, host, origin, username, credId, orgId, appId):
        self.host = host
        self.origin = "https://" + origin
        self.username = username
        self.credId = credId
        self.orgId = orgId
        self.appId = appId
        self.publicKeyPem = ''
        self.privateKeyPem = ''
        self.challengeIdentifier = ''
        self.challenge = ''
        self.authToken = ''
        self.credential = None
        self.firstFactor = {}
        
    def _setChallenge(self, challenge):
        self.challenge = challenge

    def _setChallengeIdentifier(self, authToken):
        self.challengeIdentifier = authToken

    def _setFirstFactor(self, type):
        if type.lower() == "key":
            self.firstFactor["kind"] = "Key"
            self.firstFactor["credentialAssertion"] = self.credential.getAssertion()
        else:
            raise Exception("Credential Type not implemented: %s" % type)

    def getAuthToken(self):
        return self.authToken

    def init(self):
        """Create User Login Challenge
        https://docs.dfns.co/d/api-docs/authentication/login/initlogin
        """
        initApi = DfnsAPI(self.host, "/auth/login/init", self.appId)
        data = {"username": self.username, "orgId": self.orgId}
        resp = initApi.post(data)
        self._setChallenge(resp['challenge'])
        self._setChallengeIdentifier(resp['challengeIdentifier'])
        return resp

    def completeKey(self, publicKeyPem, privateKeyPem):
        """Complete User Login
        https://docs.dfns.co/d/api-docs/authentication/login/completelogin
        """
        self.publicKeyPem = publicKeyPem
        self.privateKeyPem = privateKeyPem
        self.credential = KeyCredential(self.publicKeyPem, self.privateKeyPem, self.origin, False, self.challenge, credId=self.credId, create=False)
        self._setFirstFactor("Key")
        completeApi = DfnsAPI(self.host, "/auth/login", self.appId)
        data = {"challengeIdentifier": self.challengeIdentifier, "firstFactor": self.firstFactor}
        resp = completeApi.post(data)
        return resp

    def completeFido(self):
        pass

    def loginKey(self, publicKeyPem, privateKeyPem):
        """Login
        https://docs.dfns.co/d/api-docs/authentication/login
        """
        initResp = self.init()
        completeResp = self.completeKey(publicKeyPem, privateKeyPem)
        self.authToken = completeResp['token']
        return (initResp, completeResp)