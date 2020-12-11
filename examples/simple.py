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
