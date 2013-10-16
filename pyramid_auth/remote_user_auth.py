from pyramid.authentication import RemoteUserAuthenticationPolicy
from paste.util.import_string import eval_import

from .utils import str_to_bool
from.views import base_includeme


def includeme(config):
    settings = config.registry.settings
    func_str = settings.get('authentication.callback')
    if not func_str:
        raise AttributeError('authentication.callback '
                             'is not defined in the conf')
    callback = eval_import(func_str)
    debug = str_to_bool(settings.get('authentication.debug') or 'false')
    key = config.registry.settings.get('authentication.key') or 'REMOTE_USER'
    config.set_authentication_policy(
        RemoteUserAuthenticationPolicy(
            key,
            callback=callback,
            debug=debug,
        )
    )
    base_includeme(config)
