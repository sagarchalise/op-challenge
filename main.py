import os
import cgi
import time
import webapp2

from google.appengine.ext import ndb
from google.appengine.ext import blobstore
from google.appengine.ext.webapp import blobstore_handlers
from webapp2_extras.appengine.auth import models
from webapp2_extras import auth
from webapp2_extras import json
from webapp2_extras import jinja2
from webapp2_extras import security
from webapp2_extras import sessions

def restful(key='bad'):
    return {
        'bad': {'status': 400, 'message': "BAD REQUEST"},
        'notfound': {'status': 404, 'message': "NOT FOUND"},
        'conflict': {'status': 409, 'message': "CONFLICT"},
        'unauthorized': {'status': 401, 'message': "UNAUTHORIZED"}, 
        'forbidden': {'status': 403, 'message': "FORBIDDEN"},
        'temp': {'status': 503, 'message': "TEMPORARY SERVER ERROR"}, 
        'server': {'status': 500, 'message': "INTERNAL SERVER ERROR"} 
    }.get(key)

def user_required(handler):
    """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
    """
    def check_login(self, *args, **kwargs):
        auth = self.auth
        if not auth.get_user_by_session():
            resp = restful('unauthorized').copy()
            resp.update(error="Please login first.")
            self.jsonify(**resp)
        else:
          return handler(self, *args, **kwargs)
    return check_login

# upload_url = blobstore.create_upload_url_async("/pic")

class User(models.User):
    name = ndb.StringProperty()
    email = ndb.StringProperty()
    blob_key = ndb.BlobKeyProperty()
    
    def set_password(self, raw_password):
        """Sets the password for the current user
     
        :param raw_password:
            The raw password which will be hashed and stored
        """
        self.password = security.generate_password_hash(raw_password, length=12)
 
    @classmethod
    def get_by_auth_token(cls, user_id, token, subject='auth'):
        """Returns a user object based on a user ID and token.
        
        :param user_id:
            The user_id of the requesting user.
        :param token:
            The token string to be verified.
        :returns:
            A tuple ``(User, timestamp)``, with a user object and
            the token timestamp, or ``(None, None)`` if both were not found.
        """
        token_key = cls.token_model.get_key(user_id, subject, token)
        user_key = ndb.Key(cls, user_id)
        # Use get_multi() to save a RPC call.
        valid_token, user = ndb.get_multi([token_key, user_key])
        if valid_token and user:
            timestamp = int(time.mktime(valid_token.created.timetuple()))
            return user, timestamp
        return None, None


class BaseHandler(webapp2.RequestHandler):
    @webapp2.cached_property
    def auth(self):
        """Shortcut to access the auth instance as a property."""
        return auth.get_auth()
    
    @webapp2.cached_property
    def user_info(self):
        """Shortcut to access a subset of the user attributes that are stored
        in the session.
        
        The list of attributes to store in the session is specified in
          config['webapp2_extras.auth']['user_attributes'].
        :returns
          A dictionary with most user information
        """
        return self.auth.get_user_by_session()
    
    @webapp2.cached_property
    def user(self):
        """Shortcut to access the current logged in user.
        
        Unlike user_info, it fetches information from the persistence layer and
        returns an instance of the underlying model.
        
        :returns
          The instance of the user model associated to the logged in user.
        """
        u = self.user_info
        return self.user_model.get_by_id(u['user_id']) if u else None
    
    @webapp2.cached_property
    def user_model(self):
        """Returns the implementation of the user model.
        
        It is consistent with config['webapp2_extras.auth']['user_model'], if set.
        """   
        return self.auth.store.user_model
    
    @webapp2.cached_property
    def session(self):
        """Shortcut to access the current session."""
        return self.session_store.get_session(backend="datastore")
        
    @webapp2.cached_property
    def jinja2(self):
        # Returns a Jinja2 renderer cached in the app registry.
        return jinja2.get_jinja2(app=self.app)
    
    def render(self, _template, **context):
        # Renders a template and writes the result to the response.
        auth = 1 if self.auth.get_user_by_session() else 0
        if context:
            context.update(user=self.user_info)
            context.update(is_authenticated=auth)
        else:
            context = {'user': self.user_info, 'is_authenticated': auth}
        rv = self.jinja2.render_template(_template, **context)
        self.response.write(rv)
    
    def jsonify(self, **data):
        st = data.pop('status', 200)
        msg  = data.pop('message', "OK")
        self.response.status = '{} {}'.format(st, msg)
        self.response.status_int = st
        self.response.status_message = msg
        self.response.content_type = 'application/json'
        self.response.write(json.encode(data))

    def dispatch(self):
        # Get a session store for this request.
        self.session_store = sessions.get_store(request=self.request)
        
        try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
        finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)
    

class Message(ndb.Model):
    sender = ndb.KeyProperty(kind=User)
    reciever = ndb.KeyProperty(kind=User)
    message = ndb.TextProperty()
    title = ndb.StringProperty()
    child = ndb.KeyProperty()

class MainPage(BaseHandler):
    def get(self):
        if self.auth.get_user_by_session():
            upload_url = blobstore.create_upload_url('/upload_photo')
        template = "app.html"
        self.render(template)
        
class Register(BaseHandler):
    def post(self):
        name = self.request.get("name")
        password = self.request.get("password")
        email = self.request.get("email")
        if not (name and password and email):
            resp = restful().copy()
            resp.update(error="All the fields are  required")
        elif password != self.request.get('confirm_password'):
            resp = restful().copy()
            resp.update(error="Passwords donot match.")
        else:
            unique_properties = ['email']
            user_data = self.user_model.create_user(email, unique_properties,
                    email=email, name=name)
            if not user_data[0]:
                resp = restful('conflict').copy()
                resp.update(error="Seems like that email already exists.")
            else:
                user = user_data[1]
                user.set_password(password)
                user.put()
                resp = {'success': "User created."}
        self.jsonify(**resp)

class Login(BaseHandler):
    def post(self):
        email = self.request.get('email')
        password = self.request.get('password')
        try:
            u = self.auth.get_user_by_password(email, password, remember=True,
                save_session=True)
        except (auth.InvalidAuthIdError, auth.InvalidPasswordError) as e:
            resp = restful().copy()
            resp.update(error='Either Password  or Email  is wrong.')
        else:
            resp = {'success': 'Welcome', 'name': self.user.name}
        self.jsonify(**resp)

class Logout(BaseHandler):
    @user_required
    def get(self):
        self.auth.unset_session()
        resp = {'success': "Login Again"}
        self.jsonify(**resp)

class Users(BaseHandler):
    @user_required
    def get(self, user_key=None):
        uk = self.user.key
        q = User.query(User._key!=uk)
        if user_key is not None:
            u = ndb.Key(urlsafe=user_key).get()
            resp = {'data': {'name': u.name, 'key': u.key.urlsafe(), 'email': u.email, 'pic': u.blob_key}}
        else:
            resp = {'data': [{'key': d.key.urlsafe(), 'name':d.name, 'email': d.email, 'pic': d.blob_key} for d in q.iter()]}
        self.jsonify(**resp)
        
        
class MessageHandler(BaseHandler):
    @user_required
    def get(self, message_key=None):
        q = Message.query(Message.reciever==self.user.key)
        if message_key is not None:
            m = ndb.Key(urlsafe=message_key).get()
            resp = {'data': {'key': m.key.urlsafe(), 'sender': m.sender.get().email, 'title': m.title, 'message': m.message}}
        else:
            resp = {'data': [{'key': r.key.urlsafe(), 'sender': r.sender.get().email, 'title': r.title, 'message': r.message} for r in q.iter()]}
        self.jsonify(**resp)
    
    @user_required
    def post(self):
        to = self.request.get('to')
        msg = cgi.escape(self.request.get('msg'))
        title = cgi.escape(self.request.get('title'))
        u = self.user
        q = User.query(User.email==to).fetch()
        if not q:
            resp = restful('notfound').copy()
            resp.update(error='User <{}> not found.'.format(to))
        elif u.email == q[0].email:
            resp = restful('forbidden').copy()
            resp.update(error='Sending message to oneself is not allowed.')
        else:
            m = Message(sender=u.key, reciever=q[0].key, message=msg, title=title)
            m.put()
            resp = {'success': "Message Sent."}
        self.jsonify(**resp)
            

# class  PhotoUploadHandler(blobstore_handlers.BlobstoreUploadHandler):
    # def post(self):
        # import pdb
        # pdb.set_trace()
class PhotoUploadHandler(blobstore_handlers.BlobstoreUploadHandler, BaseHandler):    
    @user_required
    def post(self):
        import pdb
        pdb.set_trace()
        try:
            upload = self.get_uploads('file')
            u = self.get_user()
            u.blob_key = upload.key()
            u.put()
            resp = {'data': '/view_photo/{}'.format(upload.key())}
        except:
            resp = restful('server').copy()
            resp.update(error='Issue with upload.')
        self.jsonify(**resp)

class ViewPhotoHandler(BaseHandler, blobstore_handlers.BlobstoreDownloadHandler):
    @user_required
    def get(self, photo_key):
        if not blobstore.get(photo_key):
            resp = restful('notfound').copy()
            resp.update(error="Picture not found.")
            self.jsonify(**resp)
        else:
            self.send_blob(photo_key)    
    

config = {
  'webapp2_extras.auth': {
    'user_model': User,
    'user_attributes': ['name', 'email']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  }
}
application = webapp2.WSGIApplication([
    webapp2.Route('/', MainPage, name='home'),
    webapp2.Route('/register', Register, name='register'),
    webapp2.Route('/login', Login, name='login'),
    webapp2.Route('/logout', Logout, name='logout'),
    webapp2.Route('/users', Users, name='user_list'),
    webapp2.Route('/users/<user_key:\w+>', Users, name='user_detail'),
    webapp2.Route('/messages', MessageHandler, name='message_list'),
    webapp2.Route('/messages/<message_key:\w+>', MessageHandler, name='message_detail'),
    webapp2.Route('/upload_photo', PhotoUploadHandler),
    webapp2.Route('/view_photo/([^/]+)?', ViewPhotoHandler),
], debug=True, config=config)
