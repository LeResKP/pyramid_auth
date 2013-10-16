from pyramid.authorization import ACLAuthorizationPolicy
from paste.util.import_string import eval_import


def includeme(config):
    settings = config.registry.settings
    policy = settings.get('authentication.policy') or 'cookie'

    if policy not in ['cookie', 'remote_user']:
        raise Exception('Policy not supported: %s' % policy)

    mod = eval_import('pyramid_auth.%s_auth' % policy)
    mod.includeme(config)
    config.set_authorization_policy(ACLAuthorizationPolicy())

    sqladmin_dir = 'pyramid_auth:templates'
    if type(settings['mako.directories']) is list:
        settings['mako.directories'] += [sqladmin_dir]
    else:
        settings['mako.directories'] += '\n%s' % sqladmin_dir
