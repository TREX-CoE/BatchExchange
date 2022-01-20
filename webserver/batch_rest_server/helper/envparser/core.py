__all__ = ["Env"]

import os
import typing
from collections import namedtuple

class Env:
    def __init__(self, var: str = None, parser = str, default = None, required: bool = False, unset: bool = False):
        """Represent envvar parser entry.

        :param var: Environment variable name
        :param parser: Convert function and validator for field
        :param default: Default if value is missing
        :param required: Whether to fail on missing value
        :param unset: Whether to remove var envvar after reading (useful to hide secrets from child processes)
        """
        self.var = var
        self.parser = parser
        self.default = default
        self.required = required # use seperate required bool like argparse instead of object() sentinel
        self.unset = unset

    def get(self, var=None, namespace=None, environ = os.environ, name_transform=str, unsetter=lambda e, k: e.pop(k)):
        var = self.var if var is None else var
        if var is None:
            raise TypeError("No environment name specified")
        varname = name_transform(var)
        try:
            val = environ[varname]
            if unsetter is not None and self.unset:
                unsetter(environ, varname)

        except KeyError as e:
            if not namespace is None and self.var in namespace:
                var = namespace[self.var]
            elif self.required:
                # from None to explicitly suppress KeyError
                raise ValueError("Missing required environment variable '{}'".format(varname)) from None
            else:
                val = self.default
        else:
            val = self.parser(val)

        return (var, val)
