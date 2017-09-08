import os
import jinja2
import webapp2
import re
from google.appengine.ext import db
import hashlib


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# Checks User session


def checkUser(self):

    if self.request.cookies.get("user_id"):
        user_key = self.request.cookies.get("user_id").split("|")[0]
        hash_key = self.request.cookies.get("user_id").split("|")[1]
        if valid_pw(user_key, hash_key):
            user_key = db.Key.from_path('UserDB', int(user_key),
                                        parent=signup_key())

            if user_key:
                return True
            else:
                return False
        else:
            return False
    else:
        return False
# Main Handler class that provides methods to render HTML/Text


class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

# Databases User and Blog
# User Datastore


class UserDB(db.Model):
    username = db.StringProperty()
    password = db.StringProperty()
    email = db.StringProperty()

# dummy parent for the userDB


def signup_key(name='default'):
    return db.Key.from_path('signup', name)


# User Accounts and Security

# Password Hashing
def make_pw_hash(pw):
    h = hashlib.sha256(pw).hexdigest()
    return h


def valid_pw(pw, h):
    return h == make_pw_hash(pw)


# Validation Rules
def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)


def valid_password(pwd):
    PWD_RE = re.compile(r"^.{3,20}$")
    return PWD_RE.match(pwd)


def valid_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return EMAIL_RE.match(email)


# Handler for User Registration
class SignUp(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        count = 0
        username = self.request.get("username")
        pwd = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")
        usererror = ""
        pwderror = ""
        cmperror = ""
        emailerror = ""

        db1 = UserDB(parent=signup_key(), username=username,
                     password=hashlib.sha256(pwd).hexdigest(), email=email)
        check = db.GqlQuery(""" select * from UserDB where username = :name
                            """, name=username).get()

        if check:
            usererror = "User exists in the system"
            count += 1

        else:
            if valid_username(username):

                if valid_password(pwd):
                    if verify != pwd:
                        cmperror = "Your passwords didn't match."
                        count += 1
                elif not valid_password(pwd):
                    pwderror = "That wasn't a valid password."
                    count += 1

            elif not valid_username(username):
                usererror = "That's not a valid username."
                count += 1
                if valid_password(pwd):
                    if verify != pwd:
                        cmperror = "Your passwords didn't match."
                        count += 1
                elif not valid_password(pwd):
                    pwderror = "That wasn't a valid password."
                    count += 1

            if email:
                if not valid_email(email):
                    emailerror = "That's not a valid email."
                    count += 1

        if count > 0:
            self.render("signup.html", username=username, email=email,
                        usererror=usererror, pwderror=pwderror,
                        cmperror=cmperror, emailerror=emailerror)

        elif count == 0:
            db1.put()
            user_id = str(db1.key().id())

            self.response.headers.add_header('Set-Cookie',
                                             'user_id=%s|%s; Path=/' %
                                             (str(user_id),
                                              make_pw_hash(user_id)))
            self.redirect('/welcome')


class Welcome(Handler):
    def get(self):

        rcookie = self.request.cookies.get('user_id')

        if rcookie == "":
            self.redirect("/signup")
        else:

            user_id = rcookie.split("|")[0]
            h = rcookie.split("|")[1]

            if h == make_pw_hash(user_id):

                key = db.Key.from_path('UserDB', int(user_id),
                                       parent=signup_key())

                user = db.get(key)

                self.render("welcome.html", username=user.username)

            else:
                self.redirect("/signup")


class Login(Handler):
    def get(self):
        self.render("login.html")

    def post(self):

        username = self.request.get("username")
        pwd = self.request.get("password")
        check = db.GqlQuery("select * from UserDB where username= :name",
                            name=username,
                            pwd=hashlib.sha256(pwd).hexdigest()).get(keys_only=True)  # noqa

        if not check:
            error = "Invalid login"
            self.render("login.html", error=error)

        else:
            user_id = check.id()
            self.response.headers.add_header('Set-Cookie',
                                             'user_id=%s|%s; Path=/' %
                                             (str(user_id),
                                              make_pw_hash(str(user_id))))

            self.redirect('/welcome')


class LogOut(Handler):
    def get(self):
        a = ""

        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/'
                                         % a)
        self.redirect("/blog")
# -----------------------------------------------------------------------------------------------------------------------
# Blog


class BlogDB(db.Model):

    user = db.ReferenceProperty(UserDB, collection_name='posts')

    subject = db.StringProperty()
    blogentry = db.TextProperty()
    like = db.StringProperty()
    likecheck = db.StringProperty()

    created = db.DateTimeProperty(auto_now=True)
# dummy parent for the BlogDB


def blog_key(name='default'):
    return db.Key.from_path('blogs', name)


# Handler for the main page, can render HTML with the list of all blog
# entries in the Datastore


class Blog(Handler):
    def get(self):
        blogs = db.GqlQuery("""select * from BlogDB order by created DESC limit
                            4""")
        user_id = self.request.cookies.get("user_id")

        self.render("index.html", blogs=blogs, user_id=user_id)


class BlogGetbyId(Handler):
    def get(self, key):
        key = db.Key.from_path('BlogDB', int(key), parent=blog_key())

        blog = db.get(key)

        if not blog:

            self.redirect("/blog")
            return

        # Get the user details for the author of the blog
        user_id1 = BlogDB.user.get_value_for_datastore(blog).id()
        key = db.Key.from_path('UserDB', int(user_id1), parent=signup_key())
        user = db.get(key)

        self.render("blogpost.html",
                    blog=blog, comments=blog.blogposts, user=user)


class NewPost(Handler):
    def get(self):

        if checkUser(self):

            self.render("newpost.html")

        else:
            self.redirect("/login")

    def post(self):

        if checkUser(self):

            user_key = self.request.cookies.get("user_id").split("|")[0]
            user_key = db.Key.from_path('UserDB', int(user_key),
                                        parent=signup_key())

            subject = self.request.get("subject")
            blogentry = self.request.get("blogentry")

            if subject and blogentry:

                blog = BlogDB(user=user_key, parent=blog_key(),
                              subject=subject, blogentry=blogentry)
                blog.put()

                key = str(blog.key().id())

                self.redirect("/blog/" + key)

            else:
                error = "Subject and content please!!"
                self.render("newpost.html", subject=subject,
                            blogentry=blogentry, error=error)
        else:

            self.redirect("/login")


class EditPost(Handler):

    def get(self, key):

        if checkUser(self):

            key1 = db.Key.from_path('BlogDB', int(key), parent=blog_key())
            blog = db.get(key1)
            user_key = self.request.cookies.get("user_id").split("|")[0]
            user_id1 = BlogDB.user.get_value_for_datastore(blog).id()
            key2 = db.Key.from_path('UserDB', int(user_id1),
                                    parent=signup_key())
            user = db.get(key2)

            if int(user_key) == int(user_id1):

                self.render("edit.html", blog=blog)

            else:

                editerror = "You can only edit posts created by you"

                self.render("blogpost.html", blog=blog,
                            comments=blog.blogposts,
                            user=user, editerror=editerror)
        else:

            self.redirect("/login")

    def post(self, key):

        if checkUser(self):
            key = db.Key.from_path('BlogDB', int(key), parent=blog_key())
            blog = db.get(key)

            blog.subject = self.request.get("subject")
            blog.blogentry = self.request.get("blogentry")

            blog.put()

            key = str(blog.key().id())

            self.redirect("/blog/" + key)

        else:
            self.redirect("/login")


class DelPost(Handler):

    def get(self, key):
        key1 = db.Key.from_path('BlogDB', int(key), parent=blog_key())
        blog = db.get(key1)
        user_key = self.request.cookies.get("user_id").split("|")[0]

        if not blog:
            self.redirect("/blog")
            return

        if user_key == "":
            self.redirect("/login")
            return
        user_id1 = BlogDB.user.get_value_for_datastore(blog).id()
        key2 = db.Key.from_path('UserDB', int(user_id1), parent=signup_key())
        user = db.get(key2)

        if int(user_key) == int(user_id1):

            blog.delete()
            self.redirect("/blog")

        else:

            deleteerror = "You can only delete posts created by you"

            self.render("blogpost.html", blog=blog, comments=blog.blogposts,
                        user=user, deleteerror=deleteerror)


class LikePost(Handler):

    def get(self, key):

        key1 = key

        key = db.Key.from_path('BlogDB', int(key), parent=blog_key())
        blog = db.get(key)
        user_key = ""

        if self.request.cookies.get("user_id"):
            user_key = self.request.cookies.get("user_id").split("|")[0]

        if not blog:
            self.redirect("/blog")
            return

        if user_key == "":
            self.redirect("/login")
            return
        user_id1 = BlogDB.user.get_value_for_datastore(blog).id()
        key2 = db.Key.from_path('UserDB', int(user_id1), parent=signup_key())
        user = db.get(key2)
        if not user_key:
            self.redirect("/signup")

        if int(user_key) == int(user_id1):

            likeerror = "You can't like your own post!!!"

            self.render("blogpost.html", blog=blog, comments=blog.blogposts,
                        user=user, likeerror=likeerror)

        else:
            blogDB = BlogDB.all()
            users = blogDB.filter("likecheck", user_key+key1)
            if int(users.count()) == 0:

                if blog.like:
                    likes = int(blog.like)
                    blog.like = str(likes + 1)
                else:
                    blog.like = str(1)
                blog.likecheck = user_key+key1
                blog.put()
                key = str(blog.key().id())

                self.redirect("/blog/" + key)
            else:

                likeerror = "You can't like the same post twice!!!"

                self.render("blogpost.html", blog=blog,
                            comments=blog.blogposts,
                            user=user, likeerror=likeerror)
# -----------------------------------------------------------------------------------------------------------------------

# Activity DB


def act_key(name='default'):
    return db.Key.from_path('act', name)


class ActDB(db.Model):

    comment = db.TextProperty()

    user = db.ReferenceProperty(UserDB, collection_name='activity')
    blog = db.ReferenceProperty(BlogDB, collection_name='blogposts')

    posted = db.DateTimeProperty(auto_now=True)


class Comment(Handler):

    def get(self, key):

        if checkUser(self):
            self.render("comment.html")
        else:
            self.redirect("/login")

    def post(self, key):

        if checkUser(self):

            key1 = key

            user_key = self.request.cookies.get("user_id").split("|")[0]
            user_key = db.Key.from_path('UserDB', int(user_key),
                                        parent=signup_key())
            blogk = db.Key.from_path('BlogDB', int(key), parent=blog_key())

            comment = self.request.get("comment")

            if comment:
                act = ActDB(user=user_key, blog=blogk, parent=act_key(),
                            comment=comment)
                act.put()

                self.redirect("/blog/" + key1)

            else:
                error = "Enter comment please!!!"
                self.render("comment.html", comment=comment, error=error)

        else:
            self.redirect("/login")


class EditComment(Handler):

    def get(self, ckey, bkey):
        if checkUser(self):

            user_key = self.request.cookies.get("user_id").split("|")[0]
            key = db.Key.from_path('BlogDB', int(bkey), parent=blog_key())
            blog = db.get(key)
            ckey = db.Key.from_path('ActDB', int(ckey), parent=act_key())
            comment = db.get(ckey)

            if not comment:
                self.error(404)
                return

            user_id1 = ActDB.user.get_value_for_datastore(comment).id()

            if int(user_id1) == int(user_key):
                self.render("editcomment.html", blog=blog,
                            comment=comment, user_id=user_key)

            else:
                key2 = db.Key.from_path('UserDB', int(user_id1),
                                        parent=signup_key())
                user = db.get(key2)

                commenterror = "You can only edit your own comment"

                self.render("blogpost.html", blog=blog,
                            comments=blog.blogposts, user=user,
                            commenterror=commenterror)
        else:
            self.redirect("/login")

    def post(self, ckey, bkey):

        if checkUser(self):

            key = db.Key.from_path('BlogDB', int(bkey), parent=blog_key())
            blog = db.get(key)
            ckey = db.Key.from_path('ActDB', int(ckey), parent=act_key())
            comment = db.get(ckey)
            comment.comment = self.request.get("comment")
            comment.put()

            key = str(blog.key().id())

            self.redirect("/blog/" + key)
        else:
            self.redirect("/login")


class DeleteComment(Handler):

    def get(self, ckey, bkey):
        user_key = self.request.cookies.get("user_id").split("|")[0]

        if user_key == "":
            self.redirect("/login")
            return
        else:

            key = db.Key.from_path('BlogDB', int(bkey), parent=blog_key())
            blog = db.get(key)
            ckey = db.Key.from_path('ActDB', int(ckey), parent=act_key())
            comment = db.get(ckey)

            if not comment:

                self.error(404)
                return

            user_id1 = ActDB.user.get_value_for_datastore(comment).id()
            key2 = db.Key.from_path('UserDB', int(user_id1),
                                    parent=signup_key())
            user = db.get(key2)

            if int(user_id1) == int(user_key):

                comment.delete()

                action = "Deleted! Please refresh"

                self.render("blogpost.html", blog=blog,
                            comments=blog.blogposts, user=user, action=action)

            else:
                delerror = "You can only delete your own comment"

                self.render("blogpost.html", blog=blog,
                            comments=blog.blogposts, user=user,
                            delerror=delerror)

app = webapp2.WSGIApplication([('/blog', Blog), ('/newpost', NewPost),
                              ('/blog/(\d+)', BlogGetbyId),
                              ('/edit/(\d+)', EditPost),
                              ('/delete/(\d+)', DelPost),
                              ('/comment/(\d+)', Comment),
                              ('/like/(\d+)', LikePost),
                              ("/signup", SignUp), ("/login", Login),
                              ("/logout", LogOut), ("/welcome", Welcome),
                              ("/editcomment/(\d+)/(\d+)", EditComment),
                              ("/delcomment/(\d+)/(\d+)",
                               DeleteComment)], debug=True)

