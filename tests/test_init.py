import unittest
from pyramid.config import Configurator
from pyramid_auth import includeme


class TestIncludeme(unittest.TestCase):

    def test_unsupported_policy(self):
        settings = {}
        settings['pyramid_auth.policy'] = 'unexisting'
        config = Configurator(settings=settings)
        try:
            includeme(config)
            assert(False)
        except Exception, e:
            self.assertEqual(str(e), 'Policy not supported: unexisting')

    def test_mako_directories(self):
        settings = {}
        settings['pyramid_auth.policy'] = 'cookie'
        settings['pyramid_auth.cookie.secret'] = 'secret'
        settings['pyramid_auth.cookie.validate_function'] = 'tests.test_auth.validate_func'
        settings['mako.directories'] = 'pkg:templates'
        config = Configurator(settings=settings)
        includeme(config)
        expected = 'pkg:templates\npyramid_auth:templates'
        res = config.registry.settings['mako.directories']
        self.assertEqual(res, expected)

        settings['mako.directories'] = ['pkg:templates']
        config = Configurator(settings=settings)
        includeme(config)
        expected = ['pkg:templates', 'pyramid_auth:templates']
        res = config.registry.settings['mako.directories']
        self.assertEqual(res, expected)
