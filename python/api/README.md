# Python

This folder contains examples to use Dfns APIs with Python:
* Register a user with public/private key pair: register.py
* Login a user with public/private key pair: login.py

```python
python3 mainDfnsAuth.py --help
usage: mainDfnsAuth.py [-h] [--proxy] [--register] [--login] [--host HOST] [--origin ORIGIN] [--org ORG]
                       [--app APP] [--code CODE | --cred CRED]
                       username pubKey privKey

Example of using DFNS authentication APIs in python

positional arguments:
  username         Username
  pubKey           Public key path
  privKey          Private key path

options:
  -h, --help       show this help message and exit
  --proxy          Use HTTPS proxy. If used environment variable REQUESTS_CA_BUNDLE should be set to the
                   proxy certificate local path (export REQUESTS_CA_BUNDLE="/tmp/certificate.pem)")
                   (default: False)
  --register       Register user (default: False)
  --login          Login user (default: False)
  --host HOST      Host (default: <INSERT API HOST HERE>)
  --origin ORIGIN  Origin (default: <INSERT APP HOST HERE>)
  --org ORG        Organization ID (default: <INSERT ORG ID HERE>)
  --app APP        Application ID (default: <INSERT APP ID HERE>)
  --code CODE      Registration code (required if doing registration) (default: None)
  --cred CRED      Credential ID (required if doing login without registration) (default: None)
```
