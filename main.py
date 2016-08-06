#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# later steps:
# add https support
# study: how to do username encoding more efficiently?


import webapp2
import os
import jinja2
import hashlib
import hmac
from google.appengine.ext import ndb
import re
import string
from random import choice

template_path = os.path.join(os.path.dirname(__file__), "template")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_path), autoescape=True)
secret = "Hyperbola"


class User(ndb.Model):
    username = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=False)


def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render(self, template, **kw):
        self.write(render_str(template, **kw))


class Article(ndb.Model):
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)


class MainHandler(Handler):
    def get(self):
        articles = Article.query()
        ten_articles = articles.fetch(10)
        self.render("bloghome.html", articles = ten_articles )


def encode_username(username):
    hmac_name = hmac.new(secret, username)
    return '%s|%s' % (username, hmac_name.hexdigest())


def check_username(username_and_hmac):
    [username, hmac_name] = username_and_hmac.split('|')
    if username_and_hmac == encode_username(username):
        return username


def gensalt():
    return ''.join(choice(string.letters) for x in xrange(5))


def encode_password(password, *salt):
    if not salt:
        salt = gensalt()
    return "%s|%s"%(salt, hashlib.sha256(password+salt).hexdigest())


def check_password(password, hashed_password):
    salt = hashed_password.split('|')[0]
    return encode_password(password, salt) == hashed_password


class Welcome(Handler):
    def get(self):
        username = check_username(self.request.cookies.get('username'))
        if username:
            self.write('Welcome, %s' % username)
        # here we should let user see some nice pages. For a blog it should be the blog index page.
        else:
            self.redirect('/signup')


class SignupHandler(Handler):
    def get(self):
        self.render('signup.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')
        has_error = False
        info = dict(username=username, email=email)
        if not re.match(r"^[a-zA-Z0-9_-]{3,20}$", username):
            has_error = True
            info['usernameError'] = "That's not a valid username."
        if not re.match(r"^.{3,20}$", password):
            has_error = True
            info['passwordError'] = "That's not a valid password."
        if verify != password:
            has_error = True
            info['verifyError'] = "Your passwords didn't match."
        if email:
            if (not re.match(r'^[\S]+@[\S]+\.[\S]+$', email)):
                has_error = True
                info['emailError'] = "That's not a valid email."
        if has_error:
            self.render('signup.html', **info)
        else:
            if ndb.GqlQuery("select * from User where username='%s'" % username).get():
                info['usernameError'] = "This username has been used."
                self.render('signup.html',info)
                return
            user = User(username=username, password=encode_password(password), email=email)
            print user.password
            user.put()
            self.response.headers.add('Set-Cookie', 'username=%s' % str(encode_username(username)))
            self.redirect('/welcome')


class SigninHandler(Handler):
    def get(self):
        self.render('signin.html')

    def post(self):
        username_post = self.request.get('username')
        password_post = self.request.get('password')
        render_dict = dict(username=username_post, password=password_post)
        if not re.match(r'', username_post):
            # check regex before checking if it username exist in database, because I guess it would decrease some expense in opening database.
            # But actually it is trading off from more python calculations
            # One benefit is it can prevent sQL injection.
            render_dict['usernameError'] = "Please check your username, it's not valid."
            self.render('signin.html', **render_dict)
            return
        else:
            password_db = ndb.GqlQuery("select * from User where username='%s'" % username_post).get().username
            if not password_db:
                render_dict['usernameError'] = "This username doesn't exit, please sign up or rewrite username."
                self.render('signin.html', **render_dict)
                return
            elif not check_password(password_post, password_db):
                render_dict[
                    'passwordError'] = "Password wrong. Forget your password? You can reset your password by emailing us."
                self.render('signin.html', **render_dict)
            else:
                self.response.headers.add('username', encode_username(username_post))
                self.redirect('/welcome')


class SignoutHandler(Handler):
    def get(self):
        self.response.headers.add("Set-Cookie", "username=None; Expires = Thu, 01-Jan-1970 00:00:00 GMT")
        self.redirect('/signup')


app = webapp2.WSGIApplication(
    [('/', MainHandler), ('/signup', SignupHandler), ('/login', SigninHandler), ('/logout', SignoutHandler),
     ('/welcome', Welcome)], debug=True)