import unittest
from pyramid.config import Configurator
from pyramid_auth import includeme


class TestIncludeme(unittest.TestCase):

    def test_unsupported_policy(self):
        settings = {}
        settings['authentication.policy'] = 'unexisting'
        config = Configurator(settings=settings)
        try:
            includeme(config)
            assert(False)
        except Exception, e:
            self.assertEqual(str(e), 'Policy not supported: unexisting')

    def test_mako_directories(self):
        settings = {}
        settings['authentication.policy'] = 'cookie'
        settings['authentication.cookie.secret'] = 'secret'
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
