"""
Authentication modules for vdi are contained inside this module.
To create a new authentication module, you will need to follow this steps:
    1.- Create the authentication module, probably based on an existing one
    2.- Insert the module as child of this module
    3.- Import the class of your authentication module at __init__. For example::
        from Authenticator import SimpleAthenticator
    4.- Done. At Server restart, the module will be recognized, loaded and treated

The registration of modules is done locating subclases of :py:class:`vdi.core.auths.Authentication`
"""
import os.path
import pkgutil
import importlib
import sys

def __init__():
    """
    This imports all packages that are descendant of this package, and, after that,
    it register all subclases of authenticator as
    """
    from vdi.core import auths

    # Dinamycally import children of this package. The __init__.py files must declare authenticators as subclasses of auths.Authenticator
    pkgpath = os.path.dirname(sys.modules[__name__].__file__)  # type: ignore
    for _, name, _ in pkgutil.iter_modules([pkgpath]):
        # __import__(name, globals(), locals(), [], 1)
        importlib.import_module('.' + name, __name__)  # import module

    importlib.invalidate_caches()

    a = auths.Authenticator
    for cls in a.__subclasses__():
        auths.factory().insert(cls)


__init__()
