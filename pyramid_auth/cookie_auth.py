from pyramid.authentication import AuthTktAuthenticationPolicy
from paste.util.import_string import eval_import

from .utils import str_to_bool
from .views import BaseLoginView, login_includeme


class CookieView(BaseLoginView):

    def get_validate_func(self):
        settings = self.request.registry.settings
        func_str = settings.get('authentication.validate_function')
        if not func_str:
            raise AttributeError('authentication.validate_function '
                                 'is not defined.')
        return eval_import(func_str)


def includeme(config):
    settings = config.registry.settings
    func_str = settings.get('authentication.callback')
    if not func_str:
        raise AttributeError('authentication.callback '
                             'is not defined in the conf')
    callback = eval_import(func_str)
    debug = str_to_bool(settings.get('authentication.debug') or 'false')
    key = config.registry.settings.get('authentication.key')
    if not key:
        raise AttributeError('authentication.key not defined in the conf')
    config.set_authentication_policy(
        AuthTktAuthenticationPolicy(
            key,
            callback=callback,
            debug=debug,
            hashalg='sha512',
        )
    )
    login_includeme(CookieView, config)
