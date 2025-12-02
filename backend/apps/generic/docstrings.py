def my_import(name):
    components = name.split('.')
    mod = __import__(".".join(components[:-1]))
    for comp in components[1:]:
        mod = getattr(mod, comp)
    return mod


def override_docstring(**kwargs):
    def wrapper(func):
        if 'errors' in kwargs:
            txt = ""
            result = {}
            for err in kwargs['errors']:
                api_err = my_import(f'apps.generic.api.api_exceptions.{err}')
                api_code = getattr(api_err, 'default_code')
                api_detail = getattr(api_err, 'default_detail')
                status_code = str(getattr(api_err, 'status_code'))
                line = f'<strong>Code</strong>: {api_code} <strong>Detail</strong>: {api_detail}'
                if status_code not in result:
                    result[status_code] = [line]
                else:
                    result[status_code].append(line)
            for key in result.keys():
                txt += f'<p>{key}<p>'
                txt += '<ul>'
                for item in result[key]:
                    txt += f'<li> {item} </li>'
                txt += '</ul>'
            kwargs['errors'] = txt
        func.__doc__ = func.__doc__.format(**kwargs)
        return func
    return wrapper
