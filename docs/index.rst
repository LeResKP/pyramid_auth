.. pyramid_auth documentation master file, created by
   sphinx-quickstart on Tue Oct 15 23:28:35 2013.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

############################
pyramid_auth's documentation!
############################

.. toctree::
   :maxdepth: 2


Introduction
============

This is a plugin for pyramid which provides a simple authentication system. It supports multiple authentication policy: cookie, remote_user and ldap.


cookie policy
=============

Installation
------------

In your .ini file add `pyramid_auth` to `pyramid.includes` like this::

    pyramid.includes =
        pyramid_auth
        ...

Also you need to add `pyramid_auth` in `setup.py` in install_requires::

    install_requires=[
        ...
        'pyramid_auth'
    ]

Configuration
-------------

In your .ini file you need to set the following options:

``secret``

    The secret (a string) used for auth_tkt cookie signing.
    Required.

``callback``

    Default: ``None``.  A callback passed the userid and the
    request, expected to return ``None`` if the userid doesn't
    exist or a sequence of principal identifiers (possibly empty) if
    the user does exist.  If ``callback`` is ``None``, the userid
    will be assumed to exist with no principals.  Optional.

``cookie_name``

    Default: ``auth_tkt``.  The cookie name used
    (string).  Optional.

``secure``

    Default: ``False``.  Only send the cookie back over a secure
    conn.  Optional.

``include_ip``

    Default: ``False``.  Make the requesting IP address part of
    the authentication data in the cookie.  Optional.

    For IPv6 this option is not recommended. The ``mod_auth_tkt``
    specification does not specify how to handle IPv6 addresses, so using
    this option in combination with IPv6 addresses may cause an
    incompatible cookie. It ties the authentication ticket to that
    individual's IPv6 address.

``timeout``

    Default: ``None``.  Maximum number of seconds which a newly
    issued ticket will be considered valid.  After this amount of
    time, the ticket will expire (effectively logging the user
    out).  If this value is ``None``, the ticket never expires.
    Optional.

``reissue_time``

    Default: ``None``.  If this parameter is set, it represents the number
    of seconds that must pass before an authentication token cookie is
    automatically reissued as the result of a request which requires
    authentication.  The duration is measured as the number of seconds
    since the last auth_tkt cookie was issued and 'now'.  If this value is
    ``0``, a new ticket cookie will be reissued on every request which
    requires authentication.

    A good rule of thumb: if you want auto-expired cookies based on
    inactivity: set the ``timeout`` value to 1200 (20 mins) and set the
    ``reissue_time`` value to perhaps a tenth of the ``timeout`` value
    (120 or 2 mins).  It's nonsensical to set the ``timeout`` value lower
    than the ``reissue_time`` value, as the ticket will never be reissued
    if so.  However, such a configuration is not explicitly prevented.

    Optional.

``max_age``

    Default: ``None``.  The max age of the auth_tkt cookie, in
    seconds.  This differs from ``timeout`` inasmuch as ``timeout``
    represents the lifetime of the ticket contained in the cookie,
    while this value represents the lifetime of the cookie itself.
    When this value is set, the cookie's ``Max-Age`` and
    ``Expires`` settings will be set, allowing the auth_tkt cookie
    to last between browser sessions.  It is typically nonsensical
    to set this to a value that is lower than ``timeout`` or
    ``reissue_time``, although it is not explicitly prevented.
    Optional.

``path``

    Default: ``/``. The path for which the auth_tkt cookie is valid.
    May be desirable if the application only serves part of a domain.
    Optional.

``http_only``

    Default: ``False``. Hide cookie from JavaScript by setting the
    HttpOnly flag. Not honored by all browsers.
    Optional.

``wild_domain``

    Default: ``True``. An auth_tkt cookie will be generated for the
    wildcard domain. If your site is hosted as ``example.com`` this
    will make the cookie available for sites underneath ``example.com``
    such as ``www.example.com``.
    Optional.

``parent_domain``

    Default: ``False``. An auth_tkt cookie will be generated for the
    parent domain of the current site. For example if your site is
    hosted under ``www.example.com`` a cookie will be generated for
    ``.example.com``. This can be useful if you have multiple sites
    sharing the same domain. This option supercedes the ``wild_domain``
    option.
    Optional.

``domain``

    Default: ``None``. If provided the auth_tkt cookie will only be
    set for this domain. This option is not compatible with ``wild_domain``
    and ``parent_domain``.
    Optional.

``hashalg``

    Default: ``sha512`` (the literal string).

    Any hash algorithm supported by Python's ``hashlib.new()`` function
    can be used as the ``hashalg``.

    Cookies generated by different instances of AuthTktAuthenticationPolicy
    using different ``hashalg`` options are not compatible. Switching the
    ``hashalg`` will imply that all existing users with a valid cookie will
    be required to re-login.

    Optional.

``debug``

    Default: ``False``.  If ``debug`` is ``True``, log messages to the
    Pyramid debug logger about the results of various authentication
    steps.

    Optional.


remote_user policy
==================

Installation
------------

In your .ini file add `pyramid_auth` to `pyramid.includes` like this::

    pyramid.includes =
        pyramid_auth
        ...

Also you need to add `pyramid_auth` in `setup.py` in install_requires::

    install_requires=[
        ...
        'pyramid_auth'
    ]

Configuration
-------------

In your .ini file you need to set the following options:

``environ_key``
    Default: ``REMOTE_USER``. The key in the WSGI environ which
    provides the userid.

``callback``
    Default: ``None``.  A callback passed the userid and the request,
    expected to return None if the userid doesn't exist or a sequence of
    principal identifiers (possibly empty) representing groups if the
    user does exist.  If ``callback`` is None, the userid will be assumed
    to exist with no group principals.

``debug``
    Default: ``False``.  If ``debug`` is ``True``, log messages to the
    Pyramid debug logger about the results of various authentication
    steps.



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

