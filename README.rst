pyramid_auth
============

This is a plugin for pyramid which provides a simple authentication system.
It generates the form and the urls automatically:

    * /login: display the login form
    * /logout: logout the user
    * /forbidden: the user is redirected to this page when he is logged but doesn't have the right permission to see a page.

In a future we will be able to defined the base of the urls in the setting file.


Installation
------------

Add `pyramid_auth` in your `setup.py` in `install_requires` list

In your .ini file add `pyramid_auth` to `pyramid.includes` like this::

    pyramid.includes =
        pyramid_auth
        ...

In the same file you need to pass the function to validate the login/password like this::

    pyramid_auth.validate_function = project.module.validate_password

This function should take in parameters the login and the password, and returns a boolean: True if the password and the login match.


Optional
--------

If you want to change the rendering of the template to include your design you can:

    * Create a template in the folder templates/auth of your project named base.mak. Each templates (login, forbidden) inherit from it.
    * Create the login.mak and/or forbidden.mak templates in the folder templates/auth to overwrite the default ones.
