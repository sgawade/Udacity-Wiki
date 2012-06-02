import re 
import hmac
import time

from google.appengine.ext import db
from google.appengine.api import memcache

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
USER_RE = re.compile("^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile("^.{3,20}$")
EMAIL_RE = re.compile("^[\S]+@[\S]+\.[\S]+$")

SECRET = 'sanketgawade'

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def valid_username(username):
    return username and USER_RE.match(username)

def valid_password(password):
    return password and PASS_RE.match(password)

def valid_email(email):
    return not email or EMAIL_RE.match(email)

class Users(db.Model):
    name = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()

class WikiItems(db.Model):
    slug = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)

def all_wikis(update = False):
    key = 'all_wiki'
    all_wiki = memcache.get(key)
    if all_wiki is None or update:
        all_wiki = db.GqlQuery("select * from WikiItems "
                           "Order by created desc "
                           "limit 10")
        all_wiki = list(all_wiki)
        memcache.set(key, all_wiki)
    return all_wiki

def get_user(self):
    user = ""
    user_cookie = self.request.cookies.get('user_id')
    if user_cookie:
        u_id = user_cookie.split('|')[0]
        hpwd = user_cookie.split('|')[1]
        result = Users.get_by_id(int(u_id))
        if result:
            if result.password == hpwd:
                user = result
    return user

