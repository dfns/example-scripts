import requests
import urllib.parse

class DfnsAPI:
    
    proxy = None

    def __init__(self, host, endpoint, appId, authToken='', userActionToken='') -> None:
        self.session = requests.Session()
        self.host = host
        self.endpoint = endpoint
        self.headers = {}
        self.setAppId(appId=appId)
        if authToken != '':
            self.setAuthToken(authToken=authToken)
        if userActionToken != '':
            self.setUserActionToken(userActionToken=userActionToken)
        if DfnsAPI.proxy != None:
            self.session.proxies.update(DfnsAPI.proxy)
    
    def setAppId(self, appId):
        self.headers['X-DFNS-APPID'] = appId

    def setAuthToken(self, authToken):
        self.headers['Authorization'] = "Bearer %s" % (authToken)

    def setUserActionToken(self, userActionToken):
        self.headers['X-DFNS-USERACTION'] = userActionToken

    def post(self, data):
        url = urllib.parse.urlunparse(("https", self.host, self.endpoint, "", "", "")) 
        res = self.session.post(url, json=data, headers=self.headers) 
        if res.status_code != 200:
            raise Exception("POST to %s failed with %d" % (url, res.status_code))
        return res.json()

    def get(self, params):
        url = urllib.parse.urlunparse(("https", self.host, self.endpoint, "", urllib.parse.urlencode(params), "")) 
        res = self.session.get(url, headers=self.headers) 
        if res.status_code != 200:
            raise Exception("GET to %s failed with %d" % (url, res.status_code))
        return res.json()