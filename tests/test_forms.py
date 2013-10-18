import unittest
import tw2.core as twc
from tw2.core.validation import ValidationError
from pyramid_auth import *
import pyramid_auth.forms as forms


def validate_func(*args, **kw):
    return True


class TestUserExists(unittest.TestCase):

    def test__validate_python(self):
        validate_func = lambda request, login, pwd: pwd == 'secret'
        v = forms.UserExists(
            login='login',
            password='pwd',
            validate_func=validate_func,
            request=None
        )
        dic = {
            'login': 'Bob',
            'pwd': 'secret',
        }
        v._validate_python(dic, None)

    def test__validate_python_invalid(self):
        validate_func = lambda request, login, pwd: pwd == 'secret'
        v = forms.UserExists(
            login='login',
            password='pwd',
            validate_func=validate_func,
            request=None
        )
        dic = {
            'login': 'Bob',
            'pwd': 'secret1',
        }
        try:
            v._validate_python(dic, None)
            assert(False)
        except ValidationError, e:
            self.assertEqual(str(e), 'Please check your posted data.')

    def test__validate_python_no_validation(self):
        validate_func = lambda request, login, pwd: pwd == 'secret'
        v = forms.UserExists(
            login='login',
            password='pwd',
            validate_func=validate_func,
            request=None
        )
        dic = {
            'login': twc.validation.Invalid,
            'pwd': 'secret1',
        }
        v._validate_python(dic, None)


class TestFunctions(unittest.TestCase):

    def test_create_login_form(self):
        f = forms.create_login_form(None, validate_func)
        self.assertTrue(f)
