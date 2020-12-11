bottle-cas
==========

[![Build Status](https://travis-ci.org/Kellel/bottle-cas.svg?branch=master)](https://travis-ci.org/Kellel/bottle-cas)

A CAS Client written with bottle.py
It is a fork of the original bottle-cas package supporting python3

### Usage
```python

import bottle
from bottle import route, run, request, Bottle
from bottle_cas.client import CASClient
from bottle_cas.client import CASMiddleware
cas = CASClient()

app = bottle.default_app()
app = CASMiddleware(app, cas)

@route('/')
@cas.require
def index():
    user = request.environ['REMOTE_USER']
    return "Hello %s." % user

run(app=app)
```
A more complete example can be found within the client (bottle_cas/client.py). Try running it!

### Installation
```bash
python setup.py build
python setup.py install
```
### Configuration
There is a default configuration in the config.py file located in your python site-packages
You can override it by using parameters when initializing the CAS client

```python
cas = CASClient(cas_server="cas.acme.com",
	cas_logout_url="/cas/logout",
	cas_cookie="CAS",
	secret="SUPER_SECRET_PASSPHRASE",
	debug=False,
	cookie_path="/",
	beaker_type=file,
	beaker_data_dir="/tmp/beaker/data",
	beaker_lock_dir="/tmp/beaker/lock",
	allow_http=TRUE,
	timeout=600
	)
```

You really should only need to override `cas_server` and `secret` to get this working.




