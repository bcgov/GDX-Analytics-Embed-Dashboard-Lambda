import urllib
import base64
import json
import time
import binascii
import os
from hashlib import sha1
import hmac
import sys 
import six

def lambda_handler(event, context):
    print(event,context)

    # To access query string parameters: event['queryStringParameters']['param']
    # To access path parameters: event['pathParameters']['param']
    #if 'dashboard_id' in event:
    #    dashboard_id = event['dashboard_id']
    #if 'urlhost' in event:
    #    urlhost = event['urlhost']
    #if 'embed_domain' in event:
    #    embed_domain = event['embed_domain']
        
    embed_url = '/embed/dashboards-next/' + event['dashboard_id']
    lookerkey = os.environ['LOOKERKEY']
    # set to the URL where Looker is hosted
    lookerurl = 'analytics.gov.bc.ca'  
    

    return {
        'statusCode': 200,
        'content-type': 'application/json',
        'body': generate_embed(lookerkey,lookerurl,embed_url,event)
    }

def to_ascii(s):
  """Compatibility function for converting between Python 2.7 and 3 calls"""
  if isinstance(s, six.text_type):
    return s
  elif isinstance(s, six.binary_type):
    return "".join(map(chr, map(ord, s.decode(encoding='UTF-8'))))
  return s
  

class Looker:
    """Creating a looker class"""

    def __init__(self, host, secret):
        self.secret = secret
        self.host = host


class User:
    """Creating a user class"""

    def __init__(self, id=id, first_name=None, last_name=None,
                 permissions=[], models=[], group_ids=[],
                 external_group_id=None,
                 user_attributes={}, access_filters={}):
        self.external_user_id = json.dumps(id)
        self.first_name = json.dumps(first_name)
        self.last_name = json.dumps(last_name)
        self.permissions = json.dumps(permissions)
        self.models = json.dumps(models)
        self.access_filters = json.dumps(access_filters)
        self.user_attributes = json.dumps(user_attributes)
        self.group_ids = json.dumps(group_ids)
        self.external_group_id = json.dumps(external_group_id)


class URL:
    """Creating a URL class"""

    def __init__(self, looker, user, session_length,
                 embed_url, force_logout_login=False):
        """A init function"""
        self.looker = looker
        self.user = user
        self.path = '/login/embed/' + urllib.parse.quote_plus(embed_url)
        self.session_length = json.dumps(session_length)
        self.force_logout_login = json.dumps(force_logout_login)

    # The current time as a UNIX timestamp.
    def set_time(self):
        """A time setting function"""
        self.time = json.dumps(int(time.time()))

    # Random string cannot be repeated within an hour. Prevents an
    # attacker from re-submitting a legitimate user's URL to gather
    # information they shouldn't have.
    def set_nonce(self):
        """A function that sets a nonce"""
        self.nonce = json.dumps(to_ascii(binascii.hexlify(os.urandom(16))))

    def sign(self):
        """A sign function"""
        #  Do not change the order of these
        string_to_sign = ""
        string_to_sign = string_to_sign + self.looker.host + "\n"
        string_to_sign = string_to_sign + self.path + "\n"
        string_to_sign = string_to_sign + self.nonce + "\n"
        string_to_sign = string_to_sign + self.time + "\n"
        string_to_sign = string_to_sign + self.session_length + "\n"
        string_to_sign = string_to_sign + self.user.external_user_id + "\n"
        string_to_sign = string_to_sign + self.user.permissions + "\n"
        string_to_sign = string_to_sign + self.user.models + "\n"
        string_to_sign = string_to_sign + self.user.group_ids + "\n"
        string_to_sign = string_to_sign + self.user.external_group_id + "\n"
        string_to_sign = string_to_sign + self.user.user_attributes + "\n"
        string_to_sign = string_to_sign + self.user.access_filters

        signer = hmac.new(bytearray(self.looker.secret, 'UTF-8'),
                          string_to_sign.encode('utf8'), sha1)
        self.signature = base64.b64encode(signer.digest())

    def to_string(self):
        """Function to string"""
        self.set_time()
        self.set_nonce()
        self.sign()

        params = {'nonce':               self.nonce,
                  'time':                self.time,
                  'session_length':      self.session_length,
                  'external_user_id':    self.user.external_user_id,
                  'permissions':         self.user.permissions,
                  'group_ids':           self.user.group_ids,
                  'models':              self.user.models,
                  'external_group_id':   self.user.external_group_id,
                  'user_attributes':     self.user.user_attributes,
                  'access_filters':      self.user.access_filters,
                  'signature':           self.signature,
                  'first_name':          self.user.first_name,
                  'last_name':           self.user.last_name,
                  'force_logout_login':  self.force_logout_login}

        query_string = '&'.join(["%s=%s" % (key,
                                            urllib.parse.quote_plus(val)) for key,
                                val in params.items()])

        return "%s%s?%s" % (self.looker.host, self.path, query_string)


def generate_embed(lookerkey,lookerurl,embed_url,event):
    """A test function"""
    looker = Looker(lookerurl, lookerkey)

    user = User(event['external_user_id'],
                first_name=event['first_name'],
                last_name=event['last_name'],
                permissions=['see_lookml_dashboards', 'access_data',
                             'see_user_dashboards', 'see_looks'],
                models=['all'],
                external_group_id='AnalyticsWeb_Standalone',
                # Add additional filters here. They must match a user
                # attribute that is listed in the LookML with an access_filter}
                user_attributes={"can_see_sensitive_data": "YES", "urlhost": event['urlhost']}
                )

    # Set TTL for embed code. 60*15 = 15 minutes
    timeout = 60 * 15

    url = URL(looker,
              user,
              timeout,
              embed_url + '?'
              + 'embed_domain=' + event['embed_domain'],
              force_logout_login=True)

    return "https://" + url.to_string() 
