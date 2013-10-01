import unittest
import tw2.core as twc
from tw2.core.validation import ValidationError
from webtest import TestApp
from pyramid import testing
from pyramid.config import Configurator
from pyramid.view import view_config
from pyramid_auth import *


def validate_func(*args, **kw):
    return True


class TestUserExists(unittest.TestCase):

    def test__validate_python(self):
        validate_func = lambda login, pwd: pwd == 'secret'
        v = UserExists(login='login',
                       password='pwd',
                       validate_func=validate_func)
        dic = {
            'login': 'Bob',
            'pwd': 'secret',
        }
        v._validate_python(dic, None)

    def test__validate_python_invalid(self):
        validate_func = lambda login, pwd: pwd == 'secret'
        v = UserExists(login='login',
                       password='pwd',
                       validate_func=validate_func)
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
        validate_func = lambda login, pwd: pwd == 'secret'
        v = UserExists(login='login',
                       password='pwd',
                       validate_func=validate_func)
        dic = {
            'login': twc.validation.Invalid,
            'pwd': 'secret1',
        }
        v._validate_python(dic, None)


class TestFunctions(unittest.TestCase):

    def test_create_login_form_no_validate_function(self):
        try:
            f = create_login_form({})
            assert(False)
        except AttributeError, e:
            self.assertEqual(str(e), ('authentication.validate_function '
                                      'is not defined.'))

    def test_create_login_form(self):
        f = create_login_form({'authentication.validate_function':
                               'tests.test_init.validate_func'})
        self.assertTrue(f)

    def test_str_to_bool(self):
        self.assertEqual(str_to_bool('false'), False)
        self.assertEqual(str_to_bool('true'), True)
        try:
            str_to_bool('plop')
        except Exception, e:
            self.assertEqual(str(e), 'Unable to cast as bool plop')

    def test_get_cookie_policy(self):
        res = get_cookie_policy('key', False, lambda: [])
        self.assertTrue(res)

    def test_get_cookie_policy_no_key(self):
        try:
            res = get_cookie_policy(None, False, lambda: [])
        except Exception, e:
            self.assertEqual(str(e), 'authentication.key not defined')

    def test_get_remote_user_policy(self):
        res = get_remote_user_policy(None, False, lambda: [])
        self.assertEqual(res.environ_key, 'REMOTE_USER')

        res = get_remote_user_policy('KEY', False, lambda: [])
        self.assertEqual(res.environ_key, 'KEY')


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


class TestAuthRemoteUser(BasicAuth):

    def setUp(self):
        self.settings = SETTINGS.copy()
        self.settings['authentication.policy'] = 'remote_user'
        self.settings['authentication.key'] = None
        self.app = main({}, **self.settings)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def test_forbidden_redirect(self):
        res = self.testapp.get('/fake_forbidden', extra_environ={'REMOTE_USER': 'Bob'} , status=302)
        self.assertTrue(
            ('Location', 'http://localhost/forbidden') in res._headerlist)
