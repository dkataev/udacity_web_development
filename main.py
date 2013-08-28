import webapp2
import os
import re
import jinja2
import logging
import time
import datetime
import google.appengine.ext.db
from google.appengine.ext import db
from google.appengine.api import memcache
from util import *
from wiki_db import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    def render(self, template, **kw):
        self.response.out.write(render_str(template, **kw))
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

        
class Signup(BaseHandler):
    def get(self):
        next_url = self.request.headers.get('referer', '/')
        self.render('signup.html', next_url = next_url)
    
    def post(self):
        next_url = str(self.request.get('next_url'))
        if not next_url or next_url.startswith('/login'):
            next_url = '/'
        
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        params = dict(username = username, email = email)
        error_code = False
        accounts = list(db.GqlQuery("SELECT username FROM Users"))
        
        if not valid_username(username):
            params['username_error'] = "That's not a valid username."
            error_code = True
        else:
            if username in accounts:
                    params['username_error'] = "Username is taken."
                    error_code = True
        if not valid_password(password):
            params['password_error'] = "That's not a valid password."
            error_code = True
        if not password==verify:
            params['verify_error'] = "Password didn't match"
            error_code = True
        if not valid_email(email):
            params['email_error'] = "That's not a valid e-mail"
            error_code = True
        
        if error_code:
            self.render('signup.html', **params)
        else:
            account = Users(username = username, password = make_secure_pw(password), email = email)
            account.put()
            account_id = account.key().id()
            cookie_val = make_secure_val(str(account_id))
            self.response.headers.add_header("Set-Cookie", "username_id=%s; Path=/" % str(cookie_val))
            self.redirect(next_url)

class Login(BaseHandler):
    def get(self):
        next_url = self.request.headers.get('referer', '/')
        self.render('login.html', next_url = next_url)
        
    def post(self):
        next_url = str(self.request.get('next_url'))
        if not next_url or next_url.startswith('/login'):
            next_url = '/'
        
        username = self.request.get('username')
        pw = self.request.get('password')
        url = self.request.get('url')
        
        account = db.GqlQuery("SELECT * FROM Users WHERE username = :1", username).get()
        
        if not account:
            self.render('login.html', error = 'Invalid pair')
        else:
            pw_hash = account.password
            if check_secure_pw(pw, pw_hash):
                account_id = account.key().id()
                cookie_val = make_secure_val(str(account_id))
                self.response.headers.add_header("Set-Cookie", "username_id=%s; Path=/" % str(cookie_val))
                self.redirect(next_url)
            else:
                self.render('login.html', error = 'Invalid pair')

        
class Logout(BaseHandler):
    def get(self):
        next_url = self.request.headers.get('referer', '/')
        self.response.headers["Set-Cookie"] = "username_id=; Path=/"
        self.redirect(next_url)

class ViewPage(BaseHandler):
    def get(self, url):
        article = db.GqlQuery("SELECT * FROM Article WHERE url = :1", url).get()
        version = self.request.get('v')
        if not version:
            version = -1
        self.response.headers["Set-Cookie"] = 'referer=%s; Path=/' %url
        self.response.headers.add_header("referer", url)
        self.response.headers["referer"] = url
        version = int(version)
        if not article:
            if self.request.cookies.get('username_id'):
                self.redirect("/_edit%s" % url, permanent=False)
            else:
                self.redirect("/login?url=_edit" + url)
        else:
            if self.request.cookies.get('username_id'):
                account_id = self.request.cookies.get('username_id').split('|')[0]
                account = Users.get_by_id(int(account_id))
                self.render('view.html', url = url, article = article.history[version], username = account.username, login = True)
            else:
                self.render('view.html', login = False, article = article.history[version])
            
        
class EditPage(BaseHandler):
    def get(self, url):
        if not self.request.cookies.get('username_id'):
            #self.redirect(url)
            self.redirect('/login')
        article = db.GqlQuery("SELECT * FROM Article WHERE url = :1", url).get()
        if article:
            self.render('edit.html', url = url, article = article.text)
        else:
            self.render('edit.html', url = url, article = '')
        
    def post(self, url):
        if not self.request.cookies.get('username_id'):
            #self.redirect(url)
            self.error(400)
            return
        account_id = self.request.cookies.get('username_id').split('|')[0]
        username = Users.get_by_id(int(account_id)).username
        article = db.GqlQuery("SELECT * FROM Article WHERE url = :1", url).get()
        content = self.request.get('content')
        if article:
            article.text = content
            article.history.append(content)
            article.put()
            time.sleep(1)
        else:
            a = Article(url = url, user = username, text = content, history = [content])
            a.put()
            time.sleep(1)
        self.redirect(url)
        
class History(BaseHandler):
    def get(self, url):
        if not self.request.cookies.get('username_id'):
            login = False
            username = None
        else:
            login = True
            account_id = self.request.cookies.get('username_id').split('|')[0]
            account = Users.get_by_id(int(account_id))
        foo = db.GqlQuery("SELECT * FROM Article WHERE url = :1", url).get()
        history = foo.history
        self.render('history.html', url = url, username = account.username, login = login, history = history)
        
        
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'        
app = webapp2.WSGIApplication([('/login\/?', Login),
                                ('/logout', Logout),
                                ('/signup\/?', Signup),
                                ('/_edit' + PAGE_RE, EditPage),
                                ('/_history' + PAGE_RE, History),
                                (PAGE_RE, ViewPage)], 
                                debug = True)