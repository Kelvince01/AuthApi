from django.test import TestCase
from rest_framework.exceptions import ErrorDetail
from .models import User, SignupCode, PasswordResetCode
import re
from datetime import timedelta
from django.core import mail
from django.contrib.auth import get_user_model
from django.test.utils import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.authtoken.models import Token
from rest_framework.test import APITestCase

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


def _get_code_from_email(mail):
    match = re.search(r'\?code=([0-9a-f]+)$', mail.outbox[-1].body, re.MULTILINE)
    if match:
        code = match.group(1)
        return code
    return None


@override_settings(AUTH_EMAIL_VERIFICATION=True)
class SignupTests(APITestCase):
    def setUp(self):
        # A visitor to the site
        self.user_visitor_email = 'visitor@mail.com'
        self.user_visitor_username = 'visitor'
        self.user_visitor_pw = 'visitor'

        # A verified user on the site
        self.user_verified_email = 'user_verified@mail.com'
        self.user_verified_username = 'user_verified'
        self.user_verified_pw = 'user_verified'
        
        user = get_user_model().objects.create_user(self.user_verified_email, self.user_verified_username, self.user_verified_pw)
        user.is_verified = True
        user.save()

    def test_signup_serializer_errors(self):
        error_dicts = [
            # Email required
            {'payload': {'email': '','username': self.user_verified_username,
                         'password': self.user_visitor_pw},
             'status_code': status.HTTP_400_BAD_REQUEST,
             'error': ('email', 'This field may not be blank.')
             },
             # Username required
            {'payload': {'email': self.user_verified_email,'username': '',
                         'password': self.user_visitor_pw},
             'status_code': status.HTTP_400_BAD_REQUEST,
             'error': ('username', 'This field may not be blank.')
             },
            # Password required
            {'payload': {'email': self.user_visitor_email,'username': self.user_verified_username,
                         'password': ''},
             'status_code': status.HTTP_400_BAD_REQUEST,
             'error': ('password', 'This field may not be blank.')
             },
            # Invalid email
            {'payload': {'email': 'XXX','username': self.user_verified_username,
                         'password': self.user_visitor_pw},
             'status_code': status.HTTP_400_BAD_REQUEST,
             'error': ('email', 'Enter a valid email address.')
             },
        ]

        url = reverse('authapiapp:signup')
        for error_dict in error_dicts:
            response = self.client.post(url, error_dict['payload'])

            self.assertEqual(response.status_code, error_dict['status_code'])
            #self.assertEqual(response.data[error_dict['error'][0]][0],
             #               error_dict['error'][1])
            #self.assertEqual(response.data['errors']['email'][0],
                             #error_dict['error'][1])

    def test_signup_email_already_exists(self):
        url = reverse('authapiapp:signup')
        #print(url)
        payload = {
            'email': self.user_verified_email,
            'username': self.user_verified_username,
            'password': self.user_verified_pw,
        } 
        response = self.client.post(url, payload)
        #print(str(response.data['errors']['email']))
        #for key, values in response.data.items():
            #print(key)
            #error = [value[:] for value in values]
            #print(error)
            #v = values['email']
            #s = v.string
            #print(v[0])

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        #self.assertEqual(response.data['error'],
             #            'user with this email already exists.')
        for key, values in response.data.items():
            email = values['email'][0]
            self.assertEqual(email,
                         'user with this email already exists.')

    def test_signup_username_already_exists(self):
        url = reverse('authapiapp:signup')
        payload = {
            'email': self.user_verified_email,
            'username': self.user_verified_username,
            'password': self.user_verified_pw,
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['errors']["username"][0].title(),
                         'User With This Username Already Exists.')

    def test_signup_verify_invalid_code(self):
        url = reverse('authapiapp:signup-verify')
        params = {
            'code': 'XXX',
        }
        response = self.client.get(url, params)
        #print(response.data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Unable to verify user.')

    def test_signup_and_signup_verify(self):
        # Send Signup request
        url = reverse('authapiapp:signup')
        payload = {
            'email': self.user_visitor_email,
            'username': self.user_visitor_username,
            'password': self.user_visitor_pw,
        }
        response = self.client.post(url, payload)

        # Confirm that new user created, but not verified
        user = get_user_model().objects.latest('id')
        #print(user)
        self.assertEqual(user.email, self.user_visitor_email)
        self.assertEqual(user.is_verified, False)

        # Confirm that signup code created
        signup_code = SignupCode.objects.latest('code')
        self.assertEqual(signup_code.user.email, self.user_visitor_email)

        # Confirm that email address in response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['email'], payload['email'])

        # Confirm that one email sent and that Subject correct
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject,
                         'Verify your email address')

        code = _get_code_from_email(mail)

        # Send Signup Verify request
        url = reverse('authapiapp:signup-verify')
        params = {
            'code': code,
        }
        response = self.client.get(url, params)

        # Confirm email verified successfully
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], 'Email address verified.')

    def test_signup_without_email_verification(self):

        with self.settings(AUTH_EMAIL_VERIFICATION=False):
            # Send Signup request
            url = reverse('authapiapp:signup')
            payload = {
                'email': self.user_visitor_email,
                'username': self.user_visitor_username,
                'password': self.user_visitor_pw,
            }
            self.client.post(url, payload)

            # Confirm that new user got created, and was automatically marked as verified
            # (else changing AUTH_EMAIL_VERIFICATION setting later would have horrible consequences)
            user = get_user_model().objects.latest('id')
            self.assertEqual(user.email, self.user_visitor_email)
            self.assertEqual(user.is_verified, True)

            # no verification email sent
            self.assertEqual(len(mail.outbox), 1)
            self.assertEqual(mail.outbox[0].subject,
                             'Welcome')

    def test_signup_twice_then_email_verify(self):
        # Signup mulitple times with same credentials
        num_signups = 2
        self.assertTrue(num_signups > 1)
        for i in range(0, num_signups):
            url = reverse('authapiapp:signup')
            payload = {
                'email': self.user_visitor_email,
                'username': self.user_visitor_username,
                'password': self.user_visitor_pw,
            }
            response = self.client.post(url, payload)

            self.assertEqual(response.status_code, status.HTTP_201_CREATED)
            self.assertEqual(response.data['email'], payload['email'])
            self.assertEqual(SignupCode.objects.count(), 1)
            self.assertEqual(len(mail.outbox), i+1)
            self.assertEqual(mail.outbox[i].subject,
                             'Verify your email address')

        code = _get_code_from_email(mail)

        # Send Signup Verify request
        url = reverse('authapiapp:signup-verify')
        params = {
            'code': code,
        }
        response = self.client.get(url, params)

        # Confirm email verified successfully
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], 'Email address verified.')

        # Confirm all signup codes were removed
        self.assertEqual(SignupCode.objects.count(), 0)

        # Confirm multiple signups resulted in only one additional user login
        self.assertEqual(get_user_model().objects.count(), 1+1)

'''
class LoginTests(APITestCase):
    def setUp(self):
        # User who is verified on the site
        self.user_verified_email = 'user_verified@mail.com'
        self.user_verified_username = 'user_verified',
        self.user_verified_pw = 'user_verified'
        self.user_verified = get_user_model().objects.create_user(self.user_verified_email, self.user_not_verified_username, self.user_verified_pw)
        self.user_verified.is_verified = True
        self.user_verified.save()

        # User who is not verified yet on the site
        self.user_not_verified_email = 'user_not_verified@mail.com'
        self.user_not_verified_username = 'user_not_verified'
        self.user_not_verified_pw = 'user_not_verified'
        self.user_not_verified = get_user_model().objects.create_user(self.user_not_verified_email, self.user_not_verified_username, 'pw')
        self.user_not_verified.save()

        # User who is not active on the site
        self.user_not_active_email = 'user_not_active@mail.com'
        self.user_not_active_pw = 'user_not_active'
        self.user_not_active = get_user_model().objects.create_user(self.user_not_active_email, self.user_not_verified_username, self.user_not_active_pw)
        self.user_not_active.is_verified = True
        self.user_not_active.is_active = False
        self.user_not_active.save()

    def test_login_serializer_errors(self):
        error_dicts = [
            # Email required
            {'payload': {'email': '',
                         'password': self.user_verified_pw},
             'status_code': status.HTTP_400_BAD_REQUEST,
             'error': ('email', 'This field may not be blank.')
             },
            # Password required
            {'payload': {'email': self.user_verified_email,
                         'password': ''},
             'status_code': status.HTTP_400_BAD_REQUEST,
             'error': ('password', 'This field may not be blank.')
             },
            # Invalid email
            {'payload': {'email': 'XXX',
                         'password': self.user_verified_pw},
             'status_code': status.HTTP_400_BAD_REQUEST,
             'error': ('email', 'Enter a valid email address.')
             },
        ]

        url = reverse('authapiapp:login')
        for error_dict in error_dicts:
            response = self.client.post(url, error_dict['payload'])

            self.assertEqual(response.status_code, error_dict['status_code'])
            self.assertEqual(response.data[error_dict['error'][0]][0],
                             error_dict['error'][1])

    def test_login_invalid_credentials(self):
        # Invalid email address
        url = reverse('authapiapp:login')
        payload = {
            'email': 'XXX@mail.com',
            'password': self.user_verified_pw,
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'],
                         'Unable to login with provided credentials.')

        # Invalid password for user
        url = reverse('authapiapp:login')
        payload = {
            'email': self.user_verified_email,
            'password': 'XXX',
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'],
                         'Unable to login with provided credentials.')

    ''def test_logout_no_auth_token(self):
        url = reverse('logout')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'],
                         'Authentication credentials were not provided.')

    def test_logout_invalid_auth_token(self):
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + 'XXX')
        url = reverse('logout')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'], 'Invalid token.')

    def test_login_logout(self):
        # Log in as the user
        url = reverse('authapiapp:login')
        payload = {
            'email': self.user_verified_email,
            'password': self.user_verified_pw,
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)

        token = response.data['token']

        # Log out as the user
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + token)
        url = reverse('authapiapp:logout')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], 'User logged out.')''

    def test_login_not_verified_not_active_no_login(self):
        # Not verified user can't login
        url = reverse('authapiapp:login')
        payload = {
            'email': self.user_not_verified_email,
            'password': self.user_not_verified_pw,
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'],
                         'Unable to login with provided credentials.')

        # Not active user can't login
        url = reverse('authapiapp:login')
        payload = {
            'email': self.user_not_active_email,
            'password': self.user_not_active_pw,
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'],
                         'Unable to login with provided credentials.')'''

'''
class PasswordResetTests(APITestCase):
    def setUp(self):
        # User who is verified on the site
        self.user_verified_email = 'user_verified@mail.com'
        self.user_verified_pw = 'user_verified'
        self.user_verified_pw_reset = 'user_verified reset'
        self.user_verified = get_user_model().objects.create_user(self.user_verified_email, self.user_verified_pw)
        self.user_verified.is_verified = True
        self.user_verified.save()

        # Create auth token for user (so user logged in)
        token = Token.objects.create(user=self.user_verified)
        self.token = token.key

        # User who is not verified yet on the site
        self.user_not_verified_email = 'user_not_verified@mail.com'
        self.user_not_verified_pw = 'user_not_verified'
        self.user_not_verified = get_user_model().objects.create_user(self.user_not_verified_email, 'pw')
        self.user_not_verified.save()

        # User who is verified but not active on the site
        self.user_not_active_email = 'user_not_active@mail.com'
        self.user_not_active_pw = 'user_not_active'
        self.user_not_active = get_user_model().objects.create_user(self.user_not_active_email, self.user_not_active_pw)
        self.user_not_active.is_verified = True
        self.user_not_active.is_active = False
        self.user_not_active.save()

    def test_password_reset_serializer_errors(self):
        error_dicts = [
            # Email required
            {'payload': {'email': ''},
             'status_code': status.HTTP_400_BAD_REQUEST,
             'error': ('email', 'This field may not be blank.')
             },
            # Invalid email
            {'payload': {'email': 'XXX'},
             'status_code': status.HTTP_400_BAD_REQUEST,
             'error': ('email', 'Enter a valid email address.')
             },
        ]

        url = reverse('authapiapp:password-reset')
        for error_dict in error_dicts:
            response = self.client.post(url, error_dict['payload'])

            self.assertEqual(response.status_code, error_dict['status_code'])
            self.assertEqual(response.data[error_dict['error'][0]][0],
                             error_dict['error'][1])

    def test_password_reset_no_user_with_email(self):
        # No user with email address
        url = reverse('authapiapp:password-reset')
        payload = {
            'email': 'XXX@mail.com'
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Password reset not allowed.')

    def test_password_reset_user_not_verified_not_allowed(self):
        url = reverse('authapiapp:password-reset')
        payload = {
            'email': self.user_not_verified_email
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Password reset not allowed.')

    def test_password_reset_user_not_active_not_allowed(self):
        url = reverse('authapiapp:password-reset')
        payload = {
            'email': self.user_not_active_email
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Password reset not allowed.')

    def test_password_reset_user_verified_code_created_email_sent(self):
        # Create two past reset codes that aren't used
        password_reset_code_old1 = PasswordResetCode.objects.create_password_reset_code(
            self.user_verified)
        password_reset_code_old2 = PasswordResetCode.objects.create_password_reset_code(
            self.user_verified)
        count = PasswordResetCode.objects.filter(user=self.user_verified).count()
        self.assertEqual(count, 2)

        # Send Password Reset request
        url = reverse('authapiapp:password-reset')
        payload = {
            'email': self.user_verified_email,
        }
        response = self.client.post(url, payload)

        # Get password reset code
        password_reset_code = PasswordResetCode.objects.latest('code')

        # Confirm that old password reset codes deleted
        count = PasswordResetCode.objects.filter(user=self.user_verified).count()
        self.assertEqual(count, 1)
        self.assertNotEqual(password_reset_code.code, password_reset_code_old1.code)
        self.assertNotEqual(password_reset_code.code, password_reset_code_old2.code)

        # Confirm that password reset code created
        password_reset_code = PasswordResetCode.objects.latest('code')
        self.assertEqual(password_reset_code.user.email, self.user_verified_email)

        # Confirm that email address in response
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['email'], payload['email'])

        # Confirm that one email sent and that Subject correct
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].subject, 'Reset Your Password')

    def test_password_reset_verify_invalid_code(self):
        url = reverse('authapiapp:password-reset-verify')
        params = {
            'code': 'XXX',
        }
        response = self.client.get(url, params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Unable to verify user.')

    def test_password_reset_verify_expired_code(self):
        # Send Password Reset request
        url = reverse('authapiapp:password-reset')
        payload = {
            'email': self.user_verified_email,
        }
        self.client.post(url, payload)

        # Get password reset code and make it expire
        password_reset_code = PasswordResetCode.objects.latest('code')
        password_reset_code.created_at += timedelta(days=-(PasswordResetCode.objects.get_expiry_period()+1))
        password_reset_code.save()
        code_lapsed = password_reset_code.code

        # Confirm password reset code_lapsed can't be used
        url = reverse('authapiapp:password-reset-verify')
        params = {
            'code': code_lapsed,
        }
        response = self.client.get(url, params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Unable to verify user.')

    def test_password_reset_verify_user_verified(self):
        # Send Password Reset request
        url = reverse('authapiapp:password-reset')
        payload = {
            'email': self.user_verified_email,
        }
        self.client.post(url, payload)
        password_reset_code = PasswordResetCode.objects.latest('code')
        code = password_reset_code.code

        # Send Password Reset Verify request
        url = reverse('authapiapp:password-reset-verify')
        params = {
            'code': code,
        }
        response = self.client.get(url, params)

        # Confirm password reset successfully
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], 'Email address verified.')

    def test_password_reset_verified_serializer_errors(self):
        error_dicts = [
            # Password required
            {'payload': {'password': ''},
             'status_code': status.HTTP_400_BAD_REQUEST,
             'error': ('password', 'This field may not be blank.')
             },
        ]

        url = reverse('authapiapp:password-reset-verified')
        for error_dict in error_dicts:
            response = self.client.post(url, error_dict['payload'])

            self.assertEqual(response.status_code, error_dict['status_code'])
            self.assertEqual(response.data[error_dict['error'][0]][0],
                             error_dict['error'][1])

    def test_password_reset_verified_invalid_code(self):
        # Send Password Reset request
        url = reverse('authapiapp:password-reset')
        payload = {
            'email': self.user_verified_email,
        }
        self.client.post(url, payload)
        password_reset_code = PasswordResetCode.objects.latest('code')
        code = password_reset_code.code

        # Send Password Reset Verify request
        url = reverse('authapiapp:password-reset-verify')
        params = {
            'code': code,
        }
        response = self.client.get(url, params)

        # Send Password Reset Verified request
        url = reverse('authapiapp:password-reset-verified')
        params = {
            'code': 'XXX',
            'password': self.user_verified_pw_reset,
        }
        response = self.client.post(url, params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Unable to verify user.')

    def test_password_reset_verified_user_verified(self):
        # Send Password Reset request for not used code
        url = reverse('authapiapp:password-reset')
        payload = {
            'email': self.user_verified_email,
        }
        response = self.client.post(url, payload)
        password_reset_code = PasswordResetCode.objects.latest('code')
        code_not_used = password_reset_code.code

        # Send Password Reset request for used code
        url = reverse('authapiapp:password-reset')
        payload = {
            'email': self.user_verified_email,
        }
        self.client.post(url, payload)
        password_reset_code = PasswordResetCode.objects.latest('code')
        code_used = password_reset_code.code

        # Send Password Reset Verify request
        url = reverse('authapiapp:password-reset-verify')
        params = {
            'code': code_used,
        }
        response = self.client.get(url, params)

        # Confirm password reset verify is successful
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], 'Email address verified.')

        # Confirm old codes deleted and one remains
        num_codes = PasswordResetCode.objects.count()
        self.assertEqual(num_codes, 1)

        # Send Password Reset Verified request
        url = reverse('authapiapp:password-reset-verified')
        payload = {
            'code': code_used,
            'password': self.user_verified_pw_reset,
        }
        response = self.client.post(url, payload)

        # Confirm password reset successfully
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], 'Password reset.')

        # Confirm used code deleted and none remain
        num_codes = PasswordResetCode.objects.count()
        self.assertEqual(num_codes, 0)

        # Confirm password reset code_not_used can't be used again
        url = reverse('authapiapp:password-reset-verify')
        params = {
            'code': code_not_used,
        }
        response = self.client.get(url, params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Unable to verify user.')

        # Confirm password reset code_used can't be used again
        url = reverse('authapiapp:password-reset-verify')
        params = {
            'code': code_used,
        }
        response = self.client.get(url, params)

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(response.data['detail'], 'Unable to verify user.')

        # Confirm unable to log in with old password
        url = reverse('authapiapp:login')
        payload = {
            'email': self.user_verified_email,
            'password': self.user_verified_pw,
        }
        response = self.client.post(url, payload)

        print(response.status_code)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['error'],
                         'Unable to login with provided credentials.')

        # Confirm able to log in with new password
        url = reverse('authapiapp:login')
        payload = {
            'email': self.user_verified_email,
            'password': self.user_verified_pw_reset,
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)'''

'''
class PasswordChangeTests(APITestCase):
    def setUp(self):
        # A verified user on the site
        self.user_to_change_email = 'user_to_change@mail.com'
        self.user_to_change_pw = 'pw'
        self.user_to_change = get_user_model().objects.create_user(self.user_to_change_email, self.user_to_change_pw)
        self.user_to_change.is_verified = True
        self.user_to_change.save()

        # Create auth token for user (so user logged in)
        token = Token.objects.create(user=self.user_to_change)
        self.token = token.key

        # New password
        self.user_to_change_pw_new = 'pw new'

    def test_password_change_serializer_errors(self):
        error_dicts = [
            # Password required
            {'payload': {'password': ''},
             'status_code': status.HTTP_400_BAD_REQUEST,
             'error': ('password', 'This field may not be blank.')
             },
        ]

        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        url = reverse('authapiapp:password-change')
        for error_dict in error_dicts:
            response = self.client.post(url, error_dict['payload'])

            self.assertEqual(response.status_code, error_dict['status_code'])
            self.assertEqual(response.data[error_dict['error'][0]][0],
                             error_dict['error'][1])

    def test_password_change_no_auth_token(self):
        url = reverse('authapiapp:password-change')
        payload = {
            'password': self.user_to_change_pw_new,
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'],
                         'Authentication credentials were not provided.')

    def test_password_change_invalid_auth_token(self):
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + 'XXX')
        url = reverse('authapiapp:password-change')
        response = self.client.post(url)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'], 'Invalid token.')

    def test_password_change(self):
        # Change password
        self.client.credentials(HTTP_AUTHORIZATION='Token ' + self.token)
        url = reverse('authapiapp:password-change')
        payload = {
            'password': self.user_to_change_pw_new,
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['success'], 'Password changed.')

        # Confirm unable to log in with old password
        url = reverse('authapiapp:login')
        payload = {
            'email': self.user_to_change_email,
            'password': self.user_to_change_pw,
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertEqual(response.data['detail'],
                         'Unable to login with provided credentials.')

        # Confirm able to log in with new password
        url = reverse('authapiapp:login')
        payload = {
            'email': self.user_to_change_email,
            'password': self.user_to_change_pw_new,
        }
        response = self.client.post(url, payload)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('token', response.data)'''