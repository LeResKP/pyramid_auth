def str_to_bool(s):
    if s == 'false':
        return False
    if s == 'true':
        return True
    raise Exception('Unable to cast as bool %s' % s)
