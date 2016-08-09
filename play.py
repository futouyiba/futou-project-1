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
import webapp2
import os
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)
from google.appengine.ext import db

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a,**kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Art(db.Model):
    title = db.StringProperty(required = True)
    art = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add=True)

class MainHandler(Handler):
    def render_front(self, title="", art="", error=""):
        arts = db.GqlQuery("SELECT * FROM Art ORDER BY created DESC")
        print arts
        self.render("front.html", title=title, art=art, error=error, arts=arts)

    def get(self):
        self.render_front()

    def post(self):
        title = self.request.get("title")
        art = self.request.get("art")
        if title and art:
            a = Art(title = title, art = art)
            a.put()

            self.redirect("/")
        else:
            error = "we need both a title and some artwork!"
            self.render_front(title, art, error)

class Article(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

class ArticleHandler(Handler):
    def get(self, article_id):
        article = Article.get_by_id(int(article_id))
        self.render("blogpost.html", subject=article.subject, content=article.content, created=article.created)

class PostHandler(Handler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        article = Article(subject=subject, content=content)
        article.put()
        id = article.key().id()
        self.redirect("/blog/%d"%id)


class BlogHandler(Handler):
    def get(self):
        articles = db.GqlQuery("select * from Article order by created desc")
        self.render("bloghome.html", articles=articles)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    (r'/blog',BlogHandler),
    (r'/blog/(\d+)', ArticleHandler),
    (r'/blog/newpost', PostHandler),
], debug=True)
