from django.test import TestCase

# Create your tests here.
#from django.contrib.auth.models import User
from .models import User


# Create your tests here.

class UserTestCase(TestCase):
    def test_user(self):
        email = 'sample@gmail.com'
        username = 'sample'
        password = 'sample@123'
        u = User(email=email,username=username)
        u.set_password(password)
        u.save()
        self.assertEqual(u.email, email)
        self.assertTrue(u.check_password(password))