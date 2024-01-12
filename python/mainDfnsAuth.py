#!/usr/bin/python

import argparse
from dfnsApi import DfnsAPI
from register import Registration
from login import Login

# Burp
PROXY = {
        'http': 'http://127.0.0.1:8080',
        'https': 'http://127.0.0.1:8080'
}
# Application
APP_ID = "<INSERT APP ID HERE>"
# Org
ORG_ID = "<INSERT ORG ID HERE>"
# Host
HOST = "<INSERT API HOST HERE>"
ORIGIN = "<INSERT APP HOST HERE>"

def main(proxy, host, origin, username, code, credId, orgId, appId, publicKeyFile, privateKeyFile, doRegister, doLogin):
    publicKeyPem = ''
    privateKeyPem = ''
    curCredId = credId
    with open(publicKeyFile, 'r') as f:
        publicKeyPem = f.read()
    with open(privateKeyFile, 'r') as f:
        privateKeyPem = f.read()
    if proxy != None:
        DfnsAPI.proxy = proxy
    # REGISTER
    if doRegister:
        registration = Registration(host, origin, username, code, orgId, appId)
        registration.registerKey(publicKeyPem, privateKeyPem)
        curCredId = registration.getCredId()
        print('Credential ID: ' + curCredId)
    # LOGIN
    if doLogin:
        login = Login(host, origin, username, curCredId, orgId, appId)
        login.loginKey(publicKeyPem, privateKeyPem)
        authToken = login.getAuthToken()
        print('Credential auth token: ' + authToken)

def parseArg():
    parser = argparse.ArgumentParser(description='Example of using DFNS authentication APIs in python', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    # Optional flags
    parser.add_argument('--proxy', action='store_true', help='Use HTTPS proxy. If used environment variable REQUESTS_CA_BUNDLE should be set to the proxy certificate local path (export REQUESTS_CA_BUNDLE="/tmp/certificate.pem)")')
    parser.add_argument('--register', action='store_true', help='Register user')
    parser.add_argument('--login', action='store_true', help='Login user')
    # Arguments with defaults
    parser.add_argument('--host', default=HOST, help='Host')
    parser.add_argument('--origin', default=ORIGIN, help='Origin')
    parser.add_argument('--org', default=ORG_ID, help='Organization ID')
    parser.add_argument('--app', default=APP_ID, help='Application ID')
    # Mutually exclusive group for register/credId
    register_group = parser.add_mutually_exclusive_group()
    register_group.add_argument('--code', help='Registration code (required if doing registration)')
    register_group.add_argument('--cred', help='Credential ID (required if doing login without registration)')
    # Required arguments
    parser.add_argument('username', help='Username')
    parser.add_argument('pubKey', help='Public key path')
    parser.add_argument('privKey', help='Private key path')
    # Parse
    args = parser.parse_args()
    # Enforce constraints
    if not (args.register or args.login):
        parser.error("At least one of '--register' or '--login' is required, both can be used")
    if args.register and not args.code:  # Check for missing code when registering
        parser.error("'--code' is required for registration")
    if args.login and not args.register and not args.cred:  # Check for missing credId if only login
        parser.error("'--cred' is required for login without registration")
    return args


if __name__ == "__main__":
    args = parseArg()
    proxy = None
    if args.proxy:
        proxy = PROXY
    main(proxy, args.host, args.origin, args.username, args.code, args.cred, args.org, args.app, args.pubKey, args.privKey, args.register, args.login)