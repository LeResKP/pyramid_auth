import unittest
import tw2.core as twc
from tw2.core.validation import ValidationError
from webtest import TestApp
from pyramid import testing
from pyramid.config import Configurator
from pyramid.security import remember
from pyramid.view import view_config
from pyramid_auth import *
import pyramid_auth.forms as forms
import pyramid_auth.utils as utils


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

    def test_str_to_bool(self):
        self.assertEqual(utils.str_to_bool('false'), False)
        self.assertEqual(utils.str_to_bool('true'), True)
        try:
            utils.str_to_bool('plop')
        except Exception, e:
            self.assertEqual(str(e), 'Unable to cast as bool plop')


def callback(*args, **kw):
    return []


SETTINGS = {
    'authentication.key': 'secret',
    'authentication.debug': 'false',
    'authentication.callback': 'tests.test_init.callback',
    'authentication.validate_function': 'tests.test_init.validate_func',
    'mako.directories': 'pyramid_auth:templates',
}


@view_config(route_name='fake_forbidden', permission='edit')
def fake_forbidden(context, request):
    return True


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    config = Configurator(settings=settings)
    config.include('pyramid_auth')
    config.include('pyramid_mako')
    config.add_route(
        'fake_forbidden',
        '/fake_forbidden',
    )
    config.scan()
    return config.make_wsgi_app()


class BasicAuth(unittest.TestCase):

    def setUp(self):
        self.settings = SETTINGS.copy()
        self.app = main({}, **self.settings)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def test_login(self):
        res = self.testapp.get('/login', status=200)
        self.assertTrue('<form' in res)

    def test_login_post_invalid(self):
        res = self.testapp.post('/login', {'login': 'Bob'}, status=200)
        self.assertTrue('<form' in res)
        self.assertTrue('Enter a value' in res)

    def test_login_post(self):
        res = self.testapp.post('/login',
                                {'login': 'Bob', 'password': 'secret'},
                                status=302)
        self.assertTrue(
            ('Location', 'http://localhost/')
            in res._headerlist)
        # TODO: add test to check the cookies are set

    def test_logout(self):
        res = self.testapp.get('/logout', status=302)
        self.assertTrue(
            ('Location', 'http://localhost')
            in res._headerlist)

        res = self.testapp.get('/logout',
                               {'next': 'http://www.lereskp.fr'},
                               status=302)
        self.assertTrue(
            ('Location', 'http://www.lereskp.fr')
            in res._headerlist)

    def test_forbidden(self):
        res = self.testapp.get('/forbidden', status=200)
        self.assertTrue("You don't have the right permissions." in res)

    def test_forbidden_redirect_not_logged(self):
        res = self.testapp.get('/fake_forbidden', status=302)
        self.assertTrue(
            ('Location',
             ('http://localhost/login?next='
              'http%3A%2F%2Flocalhost%2Ffake_forbidden'))
            in res._headerlist)


class TestAuthCookie(BasicAuth):

    def __remember(self):
        request = testing.DummyRequest(environ={'SERVER_NAME': 'servername'})
        request.registry = self.app.app.registry
        headers = remember(request, 'Bob')
        return {'Cookie': headers[0][1].split(';')[0]}

    def test_forbidden_redirect(self):
        headers = self.__remember()
        res = self.testapp.get('/fake_forbidden', headers=headers, status=302)
        self.assertTrue(
            ('Location', 'http://localhost/forbidden') in res._headerlist)


class TestAuthRemoteUser(unittest.TestCase):

    def setUp(self):
        self.settings = SETTINGS.copy()
        self.settings['authentication.policy'] = 'remote_user'
        self.settings['authentication.key'] = None
        self.app = main({}, **self.settings)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def test_forbidden(self):
        res = self.testapp.get('/fake_forbidden', extra_environ={'REMOTE_USER': 'Bob'} , status=200)
        self.assertTrue("You don't have the right permissions." in res)
