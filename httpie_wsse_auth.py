"""
WsseAuth auth plugin for HTTPie.

"""
from httpie.plugins import AuthPlugin
import base64, datetime, hashlib, string, random

__version__ = '0.1.2'
__author__ = 'Andras Barthazi'
__licence__ = 'MIT'

class WsseAuth:
    def __init__(self, access_id, secret_key):
        self.access_id = access_id
        self.secret_key = secret_key

    def __call__(self, r):
        nonce = ''.join(random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") for i in range(32))
        now = datetime.datetime.utcnow()
        timestamp = now.strftime('%Y-%m-%dT%H:%M:%S+00:00')

        string = nonce + timestamp + self.secret_key
        sha1 = hashlib.sha1(string.encode('utf-8')).hexdigest()
        digest = base64.b64encode(sha1.encode('utf-8')).rstrip()

        r.headers['X-WSSE'] = 'UsernameToken Username="%s", PasswordDigest="%s", Nonce="%s", Created="%s"' % (self.access_id, digest, nonce, timestamp)
        return r

class WsseAuthPlugin(AuthPlugin):

    name = 'WsseAuth auth'
    auth_type = 'wsse-auth'
    description = 'Sign requests using the WSSE authentication method'

    def get_auth(self, username=None, password=None):
        return WsseAuth(username, password)
