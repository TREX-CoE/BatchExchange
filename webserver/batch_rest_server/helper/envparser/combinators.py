__all__ = ["chain", "either", "prefix", "nullable"]

def chain(*parsers):
    def f(s):
        for parser in parsers:
            s = parser(s)
        return s
    return f

def either(*parsers):
    def f(s):
        last_error = None
        for parser in parsers:
            try:
                return parser(s)
            except ValueError as e:
                last_error = e
        raise ValueError("Not matching any parser (last): "+str(last_error))
    return f

def prefix(message, parser):
    def f(s):
        try:
            return parser(s)
        except ValueError as e:
            raise ValueError(message+": "+e.args[0]) from e
    return f

def nullable(parser):
    def p(s):
        if s == "":
            return None
        else:
            return parser(s)
    return p
