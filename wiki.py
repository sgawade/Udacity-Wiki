import os
import webapp2
import jinja2
import time

from utils import *
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class HomePage(webapp2.RequestHandler):
    def get(self):
        user = get_user(self)
        wikis = all_wikis()
        template = jinja_env.get_template('home.html')
        self.response.out.write(template.render({"user" : user, "wikis": wikis}))

class SignUpPage(webapp2.RequestHandler):
    def write_page(self, username="", usernameerror="", passwderror="", verifyerror="", email="", emailerror=""):
        template = jinja_env.get_template('signup.html')
        self.response.out.write(template.render({
                                        "user": "",
                                        "username": username,
                                        "usernameerror": usernameerror,
                                        "passwderror": passwderror,
                                        "verifyerror": verifyerror,
                                        "email": email,
                                        "emailerror": emailerror
                                       }))

    def get(self):
        if get_user(self):
            self.redirect("/")
        else:
            self.write_page()

    def post(self):
        is_error = False
        usernameerror = ""
        passwderror = ""
        verifyerror = ""
        emailerror = ""
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        if not valid_username(username):
            usernameerror = "That's not a valid username."
            is_error = True 
        else:
            u_db = db.GqlQuery("select * from Users WHERE name='%s'" %username).get()
            if u_db:
                usernameerror = "The User Already exists."
                is_error = True 

        if not valid_password(password):
            passwderror = "That wasn't a valid password."
            is_error = True 
        elif password != verify:
            verifyerror = "Your passwords didn't match."
            is_error = True 

        if not valid_email(email):
            emailerror = "That's not a valid email."
            is_error = True 

        if is_error:
            self.write_page(username, usernameerror, passwderror, verifyerror, email, emailerror)
        else:
            hpwd = hash_str(password)
            a = Users(name=username, password=hpwd, email=email)
            userid = a.put()
            self.response.headers.add_header('Set-Cookie', 'user_id=' + str(userid.id()) + '|' + hpwd +'; Path=/')
            self.redirect("/")

class LoginPage(webapp2.RequestHandler):
    def get(self):
        if get_user(self):
            self.redirect("/")
        else:
            template = jinja_env.get_template('login.html')
            self.response.out.write(template.render({"user": ""}))

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        u_db = db.GqlQuery("select * from Users WHERE name='%s'" %username).get()
        if not u_db:
            template = jinja_env.get_template('login.html')
            self.response.out.write(template.render({'login_error': "Invalid login", 'username': username}))
        else:
            u_id = u_db.key().id()
            result = Users.get_by_id(int(u_id))
            hpwd = hash_str(password)
            if result.password == hpwd:
                self.response.headers.add_header('Set-Cookie', 'user_id=' + str(u_id) + '|' + hpwd +'; Path=/')
                self.redirect("/")
            else:
                template = jinja_env.get_template('login.html')
                self.response.out.write(template.render({'login_error': "Invalid login", 'username': username}))

class LogoutPage(webapp2.RequestHandler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=;Path=/')
        self.redirect("/")

app = webapp2.WSGIApplication([('/', HomePage),
                               ('/signup/?', SignUpPage),
                               ('/login/?', LoginPage),
                               ('/logout/?', LogoutPage),
                           #    ('/_edit/PAGE_RE/?', EditPage),
                           #    (PAGE_RE, WikiPage),
                               ],
                              debug=True)
