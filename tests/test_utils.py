import unittest
import pyramid_auth.utils as utils


class TestUtils(unittest.TestCase):

    def test_str_to_bool(self):
        self.assertEqual(utils.str_to_bool('false'), False)
        self.assertEqual(utils.str_to_bool('true'), True)
        try:
            utils.str_to_bool('plop')
        except Exception, e:
            self.assertEqual(str(e), 'Unable to cast as bool plop')

    def test_parse_settings(self):
        mapping = [
            # key, convert, required, default
            ('key', None, True, None),
            ('value', None, True, None),
        ]
        settings = {
            'key': 'my key',
            'value': 'my value',
        }
        res = utils.parse_settings(settings, mapping)
        self.assertEqual(res, settings)

    def test_parse_settings_missing_required_no_default(self):
        mapping = [
            # key, convert, required, default
            ('key', None, True, None),
            ('value', None, True, None),
        ]
        settings = {
            'key': 'my key',
        }
        try:
            utils.parse_settings(settings, mapping)
            assert(False)
        except AttributeError, e:
            self.assertEqual(str(e), 'value not defined')

    def test_parse_settings_missing_required_with_default(self):
        mapping = [
            # key, convert, required, default
            ('key', None, True, None),
            ('value', None, True, 'Default value'),
        ]
        settings = {
            'key': 'my key',
        }
        expected = {
            'key': 'my key',
            'value': 'Default value',
        }
        res = utils.parse_settings(settings, mapping)
        self.assertEqual(res, expected)

    def test_parse_settings_non_required_no_default(self):
        mapping = [
            # key, convert, required, default
            ('key', None, True, None),
            ('value', None, False, None),
        ]
        settings = {
            'key': 'my key',
        }
        expected = {
            'key': 'my key',
        }
        res = utils.parse_settings(settings, mapping)
        self.assertEqual(res, expected)

    def test_parse_settings_non_required_default(self):
        mapping = [
            # key, convert, required, default
            ('key', None, True, None),
            ('value', None, False, 'default value'),
        ]
        settings = {
            'key': 'my key',
        }
        expected = {
            'key': 'my key',
            'value': 'default value',
        }
        res = utils.parse_settings(settings, mapping)
        self.assertEqual(res, expected)

    def test_parse_settings_convert(self):
        mapping = [
            # key, convert, required, default
            ('key', None, True, None),
            ('value', int, False, None),
        ]
        settings = {
            'key': 'my key',
            'value': '10',
        }
        expected = {
            'key': 'my key',
            'value': 10,
        }
        res = utils.parse_settings(settings, mapping)
        self.assertEqual(res, expected)

    def test_parse_settings_key_not_defined(self):
        mapping = [
            # key, convert, required, default
            ('key', None, True, None),
            ('value', int, False, None),
        ]
        settings = {
            'key': 'my key',
            'value': '10',
        }
        try:
            res = utils.parse_settings(settings, mapping, 'authentication')
            assert(False)
        except Exception, e:
            self.assertEqual(str(e), 'No settings defined for authentication')

    def test_parse_settings_key(self):
        mapping = {
            "setup": [
                # key, convert, required, default
                ('key', None, True, None),
                ('value', int, False, None),
            ]
        }
        settings = {
            'setup.key': 'my key',
            'setup.value': '10',
        }
        expected = {
            'key': 'my key',
            'value': 10,
        }
        res = utils.parse_settings(settings, mapping, 'setup')
        self.assertEqual(res, expected)

    def test_parse_settings_key_with_prefix(self):
        mapping = {
            "setup": [
                # key, convert, required, default
                ('key', None, True, None),
                ('value', int, False, None),
            ]
        }
        settings = {
            'authentication.setup.key': 'my key',
            'authentication.setup.value': '10',
        }
        expected = {
            'key': 'my key',
            'value': 10,
        }
        res = utils.parse_settings(settings, mapping, 'setup',
                                 prefix='authentication')
        self.assertEqual(res, expected)
