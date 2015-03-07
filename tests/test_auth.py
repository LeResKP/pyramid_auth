import unittest
import tw2.core as twc
from webtest import TestApp
from pyramid import testing
from pyramid.config import Configurator
from pyramid_auth import *
from pyramid_auth.views import BaseLoginView
from pyramid_auth.ldap_auth import validate_ldap
from pyramid.security import Authenticated, Allow, remember
from pyramid.view import view_config
from mock import patch, MagicMock


def validate_func(request, login, password):
    if login == 'Bob':
        return True
    return False


@view_config(route_name='authenticated', renderer='json',
             permission='authenticated')
def authenticated(context, request):
    return {'content': 'the user is authenticated'}


@view_config(route_name='editor', renderer='json',
             permission='editor')
def edit(context, request):
    return {'content': 'the user is editor'}

@view_config(route_name='ldap', renderer='json',
             permission='ldap')
def ldap(context, request):
    return {'content': 'the user is ldap'}


class RootFactory(object):
    __acl__ = [
        (Allow, Authenticated, 'authenticated'),
        (Allow, 'editor', 'editor'),
        (Allow, 'ldap:user', 'ldap'),
    ]

    def __init__(self, request):
        pass


def callback(uid, *args, **kw):
    if uid == 'Bob':
        return ['editor']
    return []


def main(global_config, **settings):
    """ This function returns a Pyramid WSGI application.
    """
    settings = settings.copy()
    settings['mako.directories'] = 'pyramid_auth:templates'
    config = Configurator(settings=settings, root_factory=RootFactory)
    config.include('pyramid_ldap')
    config.include('pyramid_auth')
    config.include('pyramid_mako')
    config.add_route(
        'fake_forbidden',
        '/fake_forbidden',
    )
    config.add_route(
        'authenticated',
        '/authenticated',
    )
    config.add_route(
        'editor',
        '/editor',
    )
    config.add_route(
        'ldap',
        '/ldap',
    )
    config.scan()
    return config.make_wsgi_app()


class TestAuthRemoteUser(unittest.TestCase):
    SETTINGS = {
        'authentication.policy': 'remote_user'
    }

    def setUp(self):
        self.settings = self.SETTINGS.copy()
        self.app = main({}, **self.SETTINGS)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def test_permission(self):
        res = self.testapp.get('/authenticated',
                               extra_environ={'REMOTE_USER': 'Bob'},
                               status=200)
        self.assertTrue("the user is authenticated" in res)

    def test_no_permission(self):
        res = self.testapp.get('/authenticated', status=200)
        self.assertTrue("You don't have the right permissions." in res)

    def test_no_editor(self):
        res = self.testapp.get('/editor', status=200)
        self.assertTrue("You don't have the right permissions." in res)


class TestAuthRemoteUserCustomKey(unittest.TestCase):
    SETTINGS = {
        'authentication.remote_user.environ_key': 'HTTP_REMOTE_USER',
        'authentication.policy': 'remote_user'
    }

    def setUp(self):
        self.app = main({}, **self.SETTINGS)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def test_permission(self):
        res = self.testapp.get('/authenticated',
                               extra_environ={'HTTP_REMOTE_USER': 'Bob'},
                               status=200)
        self.assertTrue("the user is authenticated" in res)

    def test_no_permission(self):
        res = self.testapp.get('/authenticated',
                               extra_environ={'REMOTE_USER': 'Bob'},
                               status=200)
        self.assertTrue("You don't have the right permissions." in res)

    def test_no_editor(self):
        res = self.testapp.get('/editor', status=200)
        self.assertTrue("You don't have the right permissions." in res)


class TestAuthRemoteUserCallback(unittest.TestCase):
    SETTINGS = {
        'authentication.remote_user.callback': 'tests.test_auth.callback',
        'authentication.policy': 'remote_user'
    }

    def setUp(self):
        self.app = main({}, **self.SETTINGS)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def test_permission(self):
        res = self.testapp.get('/authenticated',
                               extra_environ={'REMOTE_USER': 'Bob'},
                               status=200)
        self.assertTrue("the user is authenticated" in res)

    def test_no_editor(self):
        res = self.testapp.get('/editor',
                               extra_environ={'REMOTE_USER': 'Fred'},
                               status=200)
        self.assertTrue("You don't have the right permissions." in res)

    def test_editor(self):
        res = self.testapp.get('/editor',
                               extra_environ={'REMOTE_USER': 'Bob'},
                               status=200)
        self.assertTrue("the user is editor" in res)


class TestAuthCookieFunction(unittest.TestCase):

    def test_cookie_auth(self):
        settings = {}
        settings['authentication.policy'] = 'cookie'
        config = Configurator(settings=settings)
        try:
            includeme(config)
            assert(False)
        except Exception, e:
            self.assertEqual(str(e),
                             'authentication.cookie.secret not defined')

    def test_get_validate_func(self):
        settings = {}
        settings['authentication.policy'] = 'cookie'
        settings['authentication.cookie.secret'] = 'secret'
        settings['mako.directories'] = 'pyramid_auth:templates'
        config = Configurator(settings=settings)
        try:
            includeme(config)
            assert(False)
        except Exception, e:
            self.assertEqual(
                str(e),
                'authentication.cookie.validate_function is not defined.')

        request = testing.DummyRequest(environ={'SERVER_NAME': 'servername'})
        request.registry = config.registry
        view = BaseLoginView(None, request)
        try:
            view.login()
            assert(False)
        except KeyError, e:
            self.assertEqual(
                str(e),
                "'authentication.validate_function'")

        settings['authentication.cookie.validate_function'] = 'tests.test_auth.validate_func'
        config = Configurator(settings=settings)
        includeme(config)
        request = testing.DummyRequest(environ={'SERVER_NAME': 'servername'})
        request.registry = config.registry
        view = BaseLoginView(None, request)
        res = view.login()
        self.assertTrue(res)


class TestAuthCookieLogin(unittest.TestCase):
    SETTINGS = {
        'authentication.policy': 'cookie',
        'authentication.cookie.secret': 'secret',
        'authentication.cookie.validate_function': 'tests.test_auth.validate_func',
    }

    def setUp(self):
        self.app = main({}, **self.SETTINGS)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def test_login(self):
        res = self.testapp.get('/login', status=200)
        self.assertTrue('<form' in res)

    def test_login_post_invalid(self):
        res = self.testapp.post('/login', {'login': 'Bob'}, status=200)
        self.assertTrue('<form' in res)
        self.assertTrue('Enter a value' in res)

    def test_login_post_bad_user(self):
        res = self.testapp.post('/login',
                                {'login': 'Fred', 'password': 'secret'},
                                status=200)
        self.assertTrue('<form' in res)
        self.assertTrue('Login failed. Please check your '
                        'credentials and try again.' in res)

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


class TestAuthCookie(unittest.TestCase):
    SETTINGS = {
        'authentication.policy': 'cookie',
        'authentication.cookie.secret': 'secret',
        'authentication.cookie.validate_function': 'tests.test_auth.validate_func',
    }

    def setUp(self):
        self.app = main({}, **self.SETTINGS)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def __remember(self):
        request = testing.DummyRequest(environ={'SERVER_NAME': 'servername'})
        request.registry = self.app.app.registry
        headers = remember(request, 'Bob')
        return {'Cookie': headers[0][1].split(';')[0]}

    def test_permission(self):
        res = self.testapp.get('/authenticated',
                               headers=self.__remember(),
                               status=200)
        self.assertTrue("the user is authenticated" in res)

    def test_no_permission(self):
        res = self.testapp.get('/authenticated', status=302)
        self.assertTrue(
            ('Location',
             ('http://localhost/login?next='
              'http%3A%2F%2Flocalhost%2Fauthenticated'))
            in res._headerlist)

    def test_no_editor(self):
        res = self.testapp.get('/editor', status=302)
        self.assertTrue(
            ('Location',
             ('http://localhost/login?next='
              'http%3A%2F%2Flocalhost%2Feditor'))
            in res._headerlist)

    def test_forbidden(self):
        res = self.testapp.get('/forbidden', status=200)
        self.assertTrue("You don't have the right permissions." in res)


class TestAuthCookieCallback(unittest.TestCase):
    SETTINGS = {
        'authentication.policy': 'cookie',
        'authentication.cookie.secret': 'secret',
        'authentication.cookie.validate_function': 'tests.test_auth.validate_func',
        'authentication.cookie.callback': 'tests.test_auth.callback',
    }

    def setUp(self):
        self.app = main({}, **self.SETTINGS)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def __remember(self, name):
        request = testing.DummyRequest(environ={'SERVER_NAME': 'servername'})
        request.registry = self.app.app.registry
        headers = remember(request, name)
        return {'Cookie': headers[0][1].split(';')[0]}

    def test_permission(self):
        res = self.testapp.get('/authenticated',
                               headers=self.__remember('Bob'),
                               status=200)
        self.assertTrue("the user is authenticated" in res)

    def test_no_editor(self):
        res = self.testapp.get('/editor',
                               headers=self.__remember('Fred'),
                               status=302)
        self.assertTrue(
            ('Location', ('http://localhost/forbidden'))
            in res._headerlist)

    def test_editor(self):
        res = self.testapp.get('/editor',
                               headers=self.__remember('Bob'),
                               status=200)
        self.assertTrue("the user is editor" in res)


class TestAuthLdapFunction(unittest.TestCase):

    def test_validate_ldap(self):
        mock = MagicMock()
        mock.authenticate = MagicMock(return_value=False)
        with patch('pyramid_auth.ldap_auth.get_ldap_connector',
                   return_value=mock):
            res = validate_ldap(None, 'Bob', 'secret')
            self.assertEqual(res, False)

        mock.authenticate = MagicMock(return_value=True)
        with patch('pyramid_auth.ldap_auth.get_ldap_connector',
                   return_value=mock):
            res = validate_ldap(None, 'Bob', 'secret')
            self.assertEqual(res, True)

    def test_get_validate_func(self):
        settings = {}
        settings['authentication.policy'] = 'ldap'
        settings['authentication.ldap.cookie.secret'] = 'secret'
        settings.update({
            'authentication.ldap.setup.uri': 'http://ldap.lereskp.fr',
            'authentication.ldap.setup.base_dn': 'base_dn',

            'authentication.ldap.login.base_dn': 'base_dn',
            'authentication.ldap.login.filter_tmpl': 'filter',

            'authentication.ldap.groups.base_dn': 'base_dn',
            'authentication.ldap.groups.filter_tmpl': 'filter',
        })
        settings['mako.directories'] = 'pyramid_auth:templates'
        config = Configurator(settings=settings)
        config.include('pyramid_ldap')
        includeme(config)
        request = testing.DummyRequest(environ={'SERVER_NAME': 'servername'})
        request.registry = config.registry
        view = BaseLoginView(None, request)
        func = view.get_validate_func()
        self.assertEqual(func, validate_ldap)

        settings['authentication.ldap.validate_function'] = 'tests.test_auth.validate_func'
        config = Configurator(settings=settings)
        config.include('pyramid_ldap')
        includeme(config)
        request = testing.DummyRequest(environ={'SERVER_NAME': 'servername'})
        request.registry = config.registry
        view = BaseLoginView(None, request)
        self.assertEqual(func, validate_ldap)
        self.assertTrue(func, validate_func)


class TestAuthLdapLogin(unittest.TestCase):
    SETTINGS = {
        'authentication.policy': 'ldap',
        'authentication.ldap.cookie.secret': 'secret',
        'authentication.ldap.setup.uri': 'http://ldap.lereskp.fr',

        'authentication.ldap.login.base_dn': 'base_dn',
        'authentication.ldap.login.filter_tmpl': 'filter',

        'authentication.ldap.groups.base_dn': 'base_dn',
        'authentication.ldap.groups.filter_tmpl': 'filter',
        'authentication.ldap.validate_function': 'tests.test_auth.validate_func',
    }

    def setUp(self):
        self.app = main({}, **self.SETTINGS)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def test_login(self):
        res = self.testapp.get('/login', status=200)
        self.assertTrue('<form' in res)

    def test_login_post_invalid(self):
        res = self.testapp.post('/login', {'login': 'Bob'}, status=200)
        self.assertTrue('<form' in res)
        self.assertTrue('Enter a value' in res)

    def test_login_post_bad_user(self):
        res = self.testapp.post('/login',
                                {'login': 'Fred', 'password': 'secret'},
                                status=200)
        self.assertTrue('<form' in res)
        self.assertTrue('Login failed. Please check your '
                        'credentials and try again.' in res)

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


class TestAuthLdap(unittest.TestCase):
    SETTINGS = {
        'authentication.policy': 'ldap',
        'authentication.ldap.cookie.secret': 'secret',
        'authentication.ldap.setup.uri': 'http://ldap.lereskp.fr',

        'authentication.ldap.login.base_dn': 'base_dn',
        'authentication.ldap.login.filter_tmpl': 'filter',

        'authentication.ldap.groups.base_dn': 'base_dn',
        'authentication.ldap.groups.filter_tmpl': 'filter',
        'authentication.ldap.validate_function': 'tests.test_auth.validate_func',
    }

    def setUp(self):
        self.app = main({}, **self.SETTINGS)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def __remember(self):
        request = testing.DummyRequest(environ={'SERVER_NAME': 'servername'})
        request.registry = self.app.app.registry
        headers = remember(request, 'Bob')
        return {'Cookie': headers[0][1].split(';')[0]}

    def test_permission(self):
        mock = MagicMock()
        mock.user_groups = MagicMock(return_value=[])
        with patch('pyramid_auth.ldap_auth.get_ldap_connector',
                   return_value=mock):
            res = self.testapp.get('/authenticated',
                                   headers=self.__remember(),
                                   status=200)
            self.assertTrue("the user is authenticated" in res)

    def test_permission_no_group(self):
        mock = MagicMock()
        mock.user_groups = MagicMock(return_value=None)
        with patch('pyramid_auth.ldap_auth.get_ldap_connector',
                   return_value=mock):
            res = self.testapp.get('/authenticated',
                                   headers=self.__remember(),
                                   status=200)
            self.assertTrue("the user is authenticated" in res)

    def test_no_permission(self):
        res = self.testapp.get('/authenticated', status=302)
        self.assertTrue(
            ('Location',
             ('http://localhost/login?next='
              'http%3A%2F%2Flocalhost%2Fauthenticated'))
            in res._headerlist)

    def test_no_editor(self):
        res = self.testapp.get('/editor', status=302)
        self.assertTrue(
            ('Location',
             ('http://localhost/login?next='
              'http%3A%2F%2Flocalhost%2Feditor'))
            in res._headerlist)

    def test_forbidden(self):
        res = self.testapp.get('/forbidden', status=200)
        self.assertTrue("You don't have the right permissions." in res)


class TestAuthLdapCallback(unittest.TestCase):
    SETTINGS = {
        'authentication.policy': 'ldap',
        'authentication.ldap.cookie.secret': 'secret',
        'authentication.ldap.setup.uri': 'http://ldap.lereskp.fr',

        'authentication.ldap.login.base_dn': 'base_dn',
        'authentication.ldap.login.filter_tmpl': 'filter',

        'authentication.ldap.groups.base_dn': 'base_dn',
        'authentication.ldap.groups.filter_tmpl': 'filter',
        'authentication.ldap.validate_function': 'tests.test_auth.validate_func',
        'authentication.ldap.callback': 'tests.test_auth.callback',
    }

    def setUp(self):
        self.app = main({}, **self.SETTINGS)
        self.app = twc.middleware.TwMiddleware(self.app)
        self.testapp = TestApp(self.app)

    def __remember(self, name):
        request = testing.DummyRequest(environ={'SERVER_NAME': 'servername'})
        request.registry = self.app.app.registry
        headers = remember(request, name)
        return {'Cookie': headers[0][1].split(';')[0]}

    def test_permission(self):
        mock = MagicMock()
        mock.user_groups = MagicMock(return_value=[])
        with patch('pyramid_auth.ldap_auth.get_ldap_connector',
                   return_value=mock):
            res = self.testapp.get('/authenticated',
                                   headers=self.__remember('Bob'),
                                   status=200)
            self.assertTrue("the user is authenticated" in res)

    def test_no_editor(self):
        mock = MagicMock()
        mock.user_groups = MagicMock(return_value=[])
        with patch('pyramid_auth.ldap_auth.get_ldap_connector',
                   return_value=mock):
            res = self.testapp.get('/editor',
                                   headers=self.__remember('Fred'),
                                   status=302)
            self.assertTrue(
                ('Location', ('http://localhost/forbidden'))
                in res._headerlist)

    def test_editor(self):
        mock = MagicMock()
        mock.user_groups = MagicMock(return_value=[])
        with patch('pyramid_auth.ldap_auth.get_ldap_connector',
                   return_value=mock):
            res = self.testapp.get('/editor',
                                   headers=self.__remember('Bob'),
                                   status=200)
            self.assertTrue("the user is editor" in res)

    def test_no_ldap(self):
        mock = MagicMock()
        mock.user_groups = MagicMock(return_value=[])
        with patch('pyramid_auth.ldap_auth.get_ldap_connector',
                   return_value=mock):
            res = self.testapp.get('/ldap',
                                   headers=self.__remember('Bob'),
                                   status=302)
            self.assertTrue(
                ('Location', ('http://localhost/forbidden'))
                in res._headerlist)

    def test_ldap(self):
        mock = MagicMock()
        mock.user_groups = MagicMock(return_value=[('dn_ldap', {'cn': ['user']})])
        with patch('pyramid_auth.ldap_auth.get_ldap_connector',
                   return_value=mock):
            res = self.testapp.get('/ldap',
                                   headers=self.__remember('Bob'),
                                   status=200)
            self.assertTrue("the user is ldap" in res)
