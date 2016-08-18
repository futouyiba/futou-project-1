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
from model import User, Article, Comment
import re
import string
from google.appengine.ext import ndb
from random import choice

# import logging

template_path = os.path.join(os.path.dirname(__file__), "template")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_path),
                               autoescape=True)
secret = "Hyperbola"


def render_str(template, **params):
    """generic method for rendering strings from a template."""
    t = jinja_env.get_template(template)
    return t.render(params)


def encode_user_id(user_id):
    """using a secret to encode the userID."""
    if user_id.isdigit():
        user_id = str(user_id)
    hmac_name = hmac.new(secret, user_id).hexdigest()
    return '%s|%s' % (user_id, hmac_name)


def check_user_id(user_id_and_hmac):
    """When receiving a userID cookie,
    this function can get real user ID out of the encoded string."""
    user_id = user_id_and_hmac.split('|')[0]
    if user_id_and_hmac == encode_user_id(user_id):
        return int(user_id)


def gensalt(length=5):
    """generate a salt string.
    If length isn't defined, then 5 is the default"""
    return ''.join(choice(string.letters) for x in xrange(length))


def encode_password(password, salt=None):
    """Using salt to encode the password.
    Returns a 'xxxxx|xxx...xxx' format string."""
    if not salt:
        salt = gensalt()
    # logging.debug("encodepassword"+str(salt))
    return "%s|%s" % (salt, hashlib.sha256(password + salt).hexdigest())


def check_password(hashed_password, password):
    """Using encode_password function to make sure password
     in the post accords to the password within the datastore."""
    salt = hashed_password.split('|')[0]
    # logging.debug("checkpassword"+str(salt))
    return encode_password(password, salt) == hashed_password


class Handler(webapp2.RequestHandler):
    """The basic handler for all the entries."""

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        # params['user'] = self.user
        if self.user:
            params['current_username'] = self.user.username
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = encode_user_id(val)
        self.response.headers.add('Set-Cookie',
                                  '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_user_id(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key.id()))

    def logout(self):
        self.response.headers.add('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.get_by_id(int(uid))


class MainHandler(Handler):
    """The index page of blog. Lists all articles for reading."""

    def get(self):
        articles = Article.query().order(-Article.created)
        ten_articles = articles.fetch(10)
        self.render("01blog.html", posts=ten_articles)


class Welcome(Handler):
    """The welcome page of blog."""

    def get(self):
        # username = check_username(self.request.cookies.get('username'))
        if self.user:
            self.render("01welcome.html", username=self.user.username)
        # here we should let user see some nice pages.
        #  For a blog it s hould be the blog index page.
        else:
            self.redirect('/signup')


class ArticleHandler(Handler):
    """The most complex page.
    In this page user can comment, like, unlike, edit or delete an article."""

    def get(self, article_id):
        article = Article.get_by_id(int(article_id))
        error = self.request.get("error")
        article_key = article.key
        comments = Comment.query(Comment.article_key == article_key).fetch()
        self.render("01post.html", post_id=article_id, subject=article.subject,
                    content=article.content,
                    authorname=article.by.get().username,
                    comments=comments, error=error, post=article,
                    user_key=self.user and self.user.key)

    def post(self, article_id):
        if self.user is None:
            return self.redirect('/signup')
            # return
        comment_content = self.request.get("comment")
        if comment_content:
            comment = Comment(user_key=self.user.key,
                              article_key=ndb.Key(Article, int(article_id)),
                              content=comment_content)
            # get_by_id
            comment.put()
            return self.redirect("/blog/%s" % article_id)
        else:
            article = Article.get_by_id(int(article_id))
            self.render("01post.html", subject=article.subject,
                        content=article.content,
                        authorname=article.by.get().username,
                        error="Please fill comments before post!")


class SignupHandler(Handler):
    """The signup page. Handles some regex issues."""

    def get(self):
        self.render('01signup.html')

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
            if not re.match(r'^[\S]+@[\S]+\.[\S]+$', email):
                has_error = True
                info['emailError'] = "That's not a valid email."
        if has_error:
            self.render('signup.html', **info)
        else:
            if User.query(User.username == username).get():
                info['usernameError'] = "This username has been used."
                return self.render('signup.html', **info)
            user = User(username=username, password=encode_password(password),
                        email=email)
            print user.password
            user.put()
            self.login(user)
            self.redirect('/welcome')


class SigninHandler(Handler):
    """The sign in handler mainly deals with password confirmation.
     Uses salt to encrypt."""

    def get(self):
        self.render('01signin.html')

    def post(self):
        username_post = self.request.get('username')
        password_post = self.request.get('password')
        render_dict = dict(username=username_post, password=password_post)
        if not re.match(r'^[a-zA-Z0-9_-]{3,20}$', username_post):
            # check regex before checking if it username exist in database.
            # Because I guess it would decrease some expense in database.
            # But actually it is trading off from more python calculations
            # One benefit is it can prevent sQL injection.
            render_dict[
                'usernameError'] = "Please check your username," \
                                   " it's not valid."
            return self.render('signin.html', **render_dict)
        else:
            user = User.query(User.username == username_post).get()
            password_db = user.password
            if not password_db:
                render_dict[
                    'usernameError'] = "This username doesn't exit," \
                                       " please sign up or rewrite username."
                return self.render('signin.html', **render_dict)
            elif not check_password(password_db, password_post):
                render_dict['passwordError'] = "Password wrong. Forget your " \
                                               "password? " \
                                               "You can reset your " \
                                               "password by emailing."
                self.render('signin.html', **render_dict)
            else:
                self.login(user)
                self.redirect('/welcome')


class SignoutHandler(Handler):
    """Sign out operation is simpler,
     redirecting to the signup page and clears the user_id cookie."""

    def get(self):
        self.logout()
        self.redirect('/signup')


class NewArticleHandler(Handler):
    """With new article handler user can create an article.
    Requires both subject and content."""

    def render_newblog(self, subject="", content="", error=""):
        self.render("01newpost.html", subject=subject, content=content,
                    error=error)

    def get(self):
        if self.user is None:
            self.redirect("/signup")
            return
        self.render_newblog()

    def post(self):
        if not self.user:
            return self.redirect("/signup")
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            article = Article(by=self.user.key, subject=subject,
                              content=content)
            article.put()
            article_id = article.key.id()
            self.redirect("/blog/%s" % article_id)
        else:
            self.render_newblog(subject=subject, content=content,
                                error="need both subject and content!")


class EditArticleHandler(Handler):
    """Edit article page could be effective only
     if it's the same user that wrote this article."""

    def get(self, article_id):
        if not self.user:
            return self.redirect("/signup")
        article = Article.get_by_id(int(article_id))
        if article.by != self.user.key:
            return self.redirect(
                "/blog/%s?error=You can only edit your own article!"
                % article_id)
        self.render("01editpost.html", post_id=article_id,
                    subject=article.subject, content=article.content)

    def post(self, article_id):
        if not self.user:
            return self.redirect("/signup")
        article = Article.get_by_id(int(article_id))
        if article.by != self.user.key:
            return self.redirect("/blog/%s" % article_id)
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            article.subject = subject
            article.content = content
            article.put()
            self.redirect("/blog/%s" % article_id)
        else:
            self.render("01editpost.html", post_id=article_id, subject=subject,
                        content=content,
                        error="Please make sure there is subject and content!")


class EditCommentHandler(Handler):
    """Edit comment Handler shows an
    'editcomment' page if requirements are met.
    Gives an error if no content is provided."""

    def get(self, article_id, comment_id):
        if not self.user:
            return self.redirect("/signup")
        comment = Comment.get_by_id(int(comment_id))
        if comment.user_key != self.user.key:
            return self.redirect("/blog/%s" % article_id)
        return self.render("01editcomment.html", post_id=article_id,
                    comment_id=comment_id, content=comment.content)

    def post(self, article_id, comment_id):
        if not self.user:
            return self.redirect("/signup")
        comment = Comment.get_by_id(int(comment_id))
        if comment.user_key != self.user.key:
            return self.redirect("/blog/%s" % article_id)
        content = self.request.get("content")
        if content:
            comment.content = content
            comment.put()
            self.redirect("/blog/%s" % article_id)
        else:
            self.render("01editcomment.html", post_id=article_id,
                        comment_id=comment_id, content=content,
                        error="Please make sure there is content!")


class DeleteArticleHandler(Handler):
    """If authorization right, deletes the article.
     If not, shows an error on the article page."""

    def get(self, article_id):
        if not self.user:
            return self.redirect("/signup")
        article = Article.get_by_id(int(article_id))
        if article.by != self.user.key:
            # self.redirect("/blog/%s" % article_id)
            return self.redirect(
                "/blog/%s?error=You can only delete your own article!"
                % article_id)
        ndb.Key(Article, int(article_id)).delete()


class DeleteCommentHandler(Handler):
    """If user owns the comment, do delete.
     If not, shows an error on the article page."""

    def get(self, article_id, comment_id):
        if not self.user:
            return self.redirect("/signup")
        comment = Comment.get_by_id(int(comment_id))
        if self.user.key != comment.user_key:
            return self.redirect("/blog/%s" % article_id)
        comment.key.delete()
        self.redirect("/blog/%s", article_id)


class LikeArticleHandler(Handler):
    """Deals with like operation, and then refreshes the article page."""

    def get(self, article_id):
        if not self.user:
            return self.redirect("/blog/%s" % article_id)
        article = Article.get_by_id(int(article_id))
        if self.user.key == article.by:
            return self.redirect(
                "/blog/%s?error=You can't like your own article!"
                % article_id)
        if self.user.key not in article.liked_by_users:
            article.liked_by_users.append(self.user.key)
            article.put()
        self.redirect("/blog/%s" % article_id)


class UnlikeArticleHandler(Handler):
    """Deals with unlike operation, and then refreshes the article page."""

    def get(self, article_id):
        if not self.user:
            return self.redirect("/blog/%s" % article_id)
        article = Article.get_by_id(int(article_id))
        if self.user.key in article.liked_by_users:
            article.liked_by_users.remove(self.user.key)
            article.put()
        self.redirect("/blog/%s" % article_id)


app = webapp2.WSGIApplication(
    [('/', MainHandler),
     ('/signup', SignupHandler),
     ('/login', SigninHandler),
     ('/logout', SignoutHandler),
     ('/welcome', Welcome),
     ('/blog/(\d+)', ArticleHandler),
     ('/blog/edit/(\d+)', EditArticleHandler),
     ('/newpost', NewArticleHandler),
     ('/blog/delete/(\d+)', DeleteArticleHandler),
     ('/blog/(\d+)/editcomment/(\d+)', EditCommentHandler),
     ('/blog/like/(\d+)', LikeArticleHandler),
     ('/blog/unlike/(\d+)', UnlikeArticleHandler),
     ('/blog/(\d+)/deletecomment/(\d+)',
      DeleteCommentHandler)], debug=True)
