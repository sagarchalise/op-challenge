import sys
import unittest
import hashlib
import webtest
import StringIO 
from webtest.forms import Upload
from google.appengine.api import memcache
from google.appengine.ext import ndb
from google.appengine.ext import testbed
from hello import User, application, Message


class DatstoreTestCase(unittest.TestCase):
    def setUp(self):
        # First, create an instance of the Testbed class.
        self.testapp = webtest.TestApp(application)
        self.testbed = testbed.Testbed()
        # Then activate the testbed, which prepares the service stubs for use.
        self.testbed.activate()
        # Next, declare which service stubs you want to use.
        self.testbed.init_datastore_v3_stub()
        self.testbed.init_memcache_stub()
        # Clear ndb's in-context cache between tests.
        # This prevents data from leaking between tests.
        # Alternatively, you could disable caching by
        # using ndb.get_context().set_cache_policy(False)
        ndb.get_context().clear_cache()
    
    def tearDown(self):
        self.testbed.deactivate()

    def testIndex(self):
        response = self.testapp.get('/')
        self.assertEqual(response.status_int, 200)
    
    def testRegisterAndLogin(self):
        response = self.testapp.post('/register', status=400)
        assert 'error' in response.json
        response = self.testapp.post('/register', {'name': "Sagar Chalise", 'email': "sagar@example.com",  'password': "hello", 'confirm_password':"hello1"}, status=400)
        assert response.json['error'] == 'Passwords donot match.'
        response = self.testapp.post('/register', {'name': "Sagar Chalise", 'email': "sagar@example.com",  'password': "hello", 'confirm_password':"hello"})
        assert response.status_int == 200
        assert 'success' in response.json
        response = self.testapp.post('/register', {'name': "Sagar Chalise", 'email': "sagar@example.com",  'password': "hello", 'confirm_password':"hello"}, status=409)
        assert 'error' in response.json
        response = self.testapp.post('/login', {'email': "sagar@example.com",  'password': "hello1"}, status=400)
        response = self.testapp.post('/login', {'email': "sagar@example.com",  'password': "hello"})
        # assert 'error' in response.json
    def testInsertEntity(self):
        for i in range(5):
            name = 'user{}'.format(i)
            email = '{}@example.com'.format(name)
            unique_properties = ['email']
            user_data = User.create_user(email, unique_properties,
                    email=email, name=name.upper())
            u = user_data[1]
            u.set_password(name)
            u.put()
        sender = User.query(User.email=='user1@example.com').fetch()
        reciever = User.query(User.email=='user2@example.com').fetch()
        msg = "hello there"
        m = Message(sender=sender[0].key, reciever=reciever[0].key, message=msg, title="yo")
        m.put()
    
    def testUpload(self):
        for i in range(5):
            name = 'user{}'.format(i)
            email = '{}@example.com'.format(name)
            unique_properties = ['email']
            user_data = User.create_user(email, unique_properties,
                    email=email, name=name.upper(), password_raw=name.lower())
        response = self.testapp.post('/login', {'email': "user1@example.com",  'password': "user1"})
        r = self.testapp.post('/upload_photo', {'file': Upload('hello.txt', 'hello there')})
        import pdb
        pdb.set_trace()

    def testUsersAndMessages(self):
        title = "hello there"
        msg = "hey there, how you doing?"
        for i in range(5):
            name = 'user{}'.format(i)
            email = '{}@example.com'.format(name)
            unique_properties = ['email']
            user_data = User.create_user(email, unique_properties,
                    email=email, name=name.upper(), password_raw=name.lower())
        import random
        for i in range(5):
            vl = random.sample(range(5), 1)[0]
            sender = User.query(User.email=='user{}@example.com'.format(vl)).fetch()
            reciever = User.query(User.email=='user{}@example.com'.format(vl+1 if vl<4 else 1)).fetch()
            m = Message(sender=sender[0].key, reciever=reciever[0].key, message=msg, title=title)
            m.put()
        sender = User.query(User.email=='user3@example.com').fetch()
        reciever = User.query(User.email=='user1@example.com').fetch()
        m = Message(sender=sender[0].key, reciever=reciever[0].key, message=msg, title=title)
        m.put()
        response = self.testapp.get('/users', status=401)
        response = self.testapp.post('/login', {'email': "user1@example.com",  'password': "user1"})
        response = self.testapp.get('/users')
        assert 'data' in response.json
        response = self.testapp.get('/users/{}'.format(sender[0].key.urlsafe()))
        response = self.testapp.get('/users/{}'.format(reciever[0].key.urlsafe()))
        r = self.testapp.get('/messages')
        assert 'data' in response.json
        response = self.testapp.get('/messages/{}'.format(r.json['data'][0]['key']))
        assert 'data' in  response.json
        
        
if __name__ == '__main__':
    unittest.main()
    
