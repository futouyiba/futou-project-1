from google.appengine.ext import ndb


class User(ndb.Model):
    """User model. Representing a user in this blog."""
    username = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=False)


class Article(ndb.Model):
    """The model for a specific article within this blog."""
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    pic = ndb.StringProperty(required=False)
    liked_by_users = ndb.KeyProperty(User, repeated=True)
    by = ndb.KeyProperty(User)


class Comment(ndb.Model):
    """The model for a specific comment under a article."""
    user_key = ndb.KeyProperty(User, required=True)
    article_key = ndb.KeyProperty(Article, required=True)
    content = ndb.TextProperty(required=True)

