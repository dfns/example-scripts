import base64
from credential import KeyCredential
from dfnsApi import DfnsAPI

class Registration:

    def __init__(self, host, origin, username, code, orgId, appId):
        self.host = host
        self.origin = "https://" + origin
        self.username = username
        self.code = code
        self.orgId = orgId
        self.appId = appId
        self.publicKeyPem = ''
        self.privateKeyPem = ''
        self.tempAuthToken = ''
        self.challenge = ''
        self.credential = None
        self.firstFactorCredential = {}
        
    def _setChallenge(self, challenge):
        self.challenge = challenge

    def _setTempAuthToken(self, authToken):
        self.tempAuthToken = authToken

    def _setFirstFactorCredential(self, type):
        if type.lower() == "key":
            self.firstFactorCredential["credentialKind"] = "Key"
            self.firstFactorCredential["credentialInfo"] = self.credential.getInfo()
        else:
            raise Exception("Credential Type not implemented: %s" % type)

    def getCredId(self):
        return self.credential.getCredId()

    def init(self):
        """Create User Registration Challenge
        https://docs.dfns.co/d/api-docs/authentication/registration/inituserregistration
        """
        initApi = DfnsAPI(self.host, "/auth/registration/init", self.appId)
        data = {"username": self.username, "registrationCode": self.code, "orgId": self.orgId}
        resp = initApi.post(data)
        self._setChallenge(resp['challenge'])
        self._setTempAuthToken(resp['temporaryAuthenticationToken'])
        return resp

    def completeKey(self, publicKeyPem, privateKeyPem):
        """Complete User Registration
        https://docs.dfns.co/d/api-docs/authentication/registration/completeuserregistration
        """
        self.publicKeyPem = publicKeyPem
        self.privateKeyPem = privateKeyPem
        self.credential = KeyCredential(self.publicKeyPem, self.privateKeyPem, self.origin, False, self.challenge)
        self._setFirstFactorCredential("Key")
        completeApi = DfnsAPI(self.host, "/auth/registration", self.appId, authToken=self.tempAuthToken)
        data = {"firstFactorCredential": self.firstFactorCredential}
        resp = completeApi.post(data)
        return resp

    def completeFido(self):
        pass

    def registerKey(self, publicKeyPem, privateKeyPem):
        """Registration
        https://docs.dfns.co/d/api-docs/authentication/registration
        """
        initResp = self.init()
        completeResp = self.completeKey(publicKeyPem, privateKeyPem)
        return (initResp, completeResp)