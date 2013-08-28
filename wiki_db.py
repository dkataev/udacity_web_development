from google.appengine.ext import db

class Article(db.Model):
    url = db.StringProperty(required = True)
    user = db.StringProperty(required = True)
    text = db.TextProperty(required = True)
    history = db.StringListProperty(default = '')
    created = db.DateTimeProperty(auto_now_add = True)
    lastedited = db.DateTimeProperty(auto_now = True)
    
class Users(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()