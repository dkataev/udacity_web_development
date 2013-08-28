import re
import hashlib
import hmac
import random
from string import letters

SECRET = 'uQDZLzdh65gJxoLTqmZ8'

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)
    
PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)
    
EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
    
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()
    
def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    s = h.split('|')[0]
    if h == make_secure_val(s):
        return s
        
def generate_salt():
    return ''.join(random.choice(string.letters) for x in range(5))
    
def make_secure_pw(pw, salt = None):
    if not salt:
        salt = generate_salt
    return '%s|%s' %(hashlib.sha256(str(salt) + str(pw)).hexdigest(), salt)
    
def check_secure_pw(pw, pw_hash):
    salt = pw_hash.split('|')[1]
    return make_secure_pw(pw, salt) == pw_hash