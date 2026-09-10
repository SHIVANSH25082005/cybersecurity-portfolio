try:
    from flask import g, has_request_context
except ImportError:
    has_request_context = lambda: False

def request_cached(name_prefix):
    """
    Flask request-scoped caching decorator.
    Caches function call outputs in flask.g during a single request context.
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not has_request_context():
                return func(*args, **kwargs)
            
            if not hasattr(g, 'request_cache'):
                g.request_cache = {}
                
            # Build a hashable key using string representations of arguments
            key_args = tuple(str(a) for a in args)
            key_kwargs = tuple((k, str(v)) for k, v in sorted(kwargs.items()))
            key = (name_prefix, key_args, key_kwargs)
            
            if key not in g.request_cache:
                g.request_cache[key] = func(*args, **kwargs)
            return g.request_cache[key]
            
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator
