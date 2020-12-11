#
# Bottle-CAS Client
# Forked by Bruno Ilponse
# Initial author: Kellen Fox
#
# This module aims to be a sane implementation of the CAS protocol written to be used with the bottle.py framework
#
"""
Bottle-CAS Client

CAS SSO Client for bottle applications
"""

from bottle import route, run, request, redirect, response
import bottle
import requests
from urllib.parse import urlparse
from urllib.parse import urlencode
from urllib.parse import urlunsplit
from functools import wraps
import time
import sys
from beaker.middleware import SessionMiddleware
import logging
from . import config

#  Status codes returned by function validate().
TICKET_OK      = 0        #  Valid CAS server ticket found.
TICKET_NONE    = 1        #  No CAS server ticket found.
TICKET_INVALID = 2        #  Invalid CAS server ticket found.


class CASClient():
    def __init__(self, **kwargs):
        self.logger = logging.getLogger("bottle_cas")
        self.logger.addHandler(logging.StreamHandler(sys.stdout))
        self.logger.setLevel(logging.DEBUG)


        self.CAS_SERVER = self.getParam("cas_server", config.CAS_SERVER, **kwargs)
        self.CAS_LOGOUT_URL = self.getParam("cas_logout_url", config.CAS_LOGOUT_URL, **kwargs)
        self.CAS_COOKIE = self.getParam("cas_cookie", config.CAS_COOKIE, **kwargs)
        self.SECRET = self.getParam("secret", config.SECRET, **kwargs)
        self.DEBUG = self.getParam("debug", config.DEBUG, **kwargs)
        self.COOKIE_PATH = self.getParam("cookie_path", config.COOKIE_PATH, **kwargs)

        self.BEAKER_TYPE = self.getParam("beaker_type", config.BEAKER_TYPE, **kwargs)
        self.BEAKER_DATA_DIR = self.getParam("beaker_data_dir", config.BEAKER_DATA_DIR, **kwargs)
        self.BEAKER_LOCK_DIR = self.getParam("beaker_lock_dir", config.BEAKER_LOCK_DIR, **kwargs)

        self.ALLOW_HTTP = self.getParam("allow_http", config.ALLOW_HTTP, **kwargs)
        self.TIMEOUT = self.getParam("timeout", config.TIMEOUT, **kwargs)


        self.debug("Initialized")

    # Returns a configuration parameter given its key
    def getParam(self, key, default, **kwargs):
        if key in kwargs:
            return kwargs[key]
        return default

    # Debugging utility
    def debug(self, text):
        if self.DEBUG:
            self.logger.info("[BOTTLE-CAS] " + text)

    def _do_login(self):
        url = request.urlparts
        newurl = (url[0],url[1],url[2],'',url[4])
        params = { 'service': urlunsplit(newurl) }
        cas_url = self.CAS_SERVER + "/cas/login?" + urlencode(params)
        redirect(cas_url)

    def test_login(self, fn):
        """
        Decorator to test CAS authentication status in a bottle route

        **Note** this doesn't ensure that they are logged in, just tells you if they already are
        """

        @wraps(fn)
        def wrapper(*args, **kwargs):
            session = request.environ['beaker.session']
            if 'username' in session:
                request.environ['REMOTE_USER_STATUS'] = "VALID"
            else:
                request.environ['REMOTE_USER_STATUS'] = "INVALID"
            return fn(*args, **kwargs)
        return wrapper


    def require(self, fn):
        """
        Decorator to enable CAS authentication for a bottle route

        :Usage:
           from bottle_cas import client
           cas = client()

           @route('/foo')
           @cas.require
           def foo():
          NOTE: The require statement must be used between the route definition and the function.
                If using an additional authentication scheme (LDAP) this should be defined below the CAS require

        :returns: A wrapped route that requres CAS authentication
        :rtype: `function`
        """

        @wraps(fn)
        def wrapper(*args, **kwargs):
            #cookie = request.get_cookie(self._CAS_COOKIE, secret=self._SECRET)
            session = request.environ['beaker.session']
            ticket = request.query.ticket;
            if 'username' in session:
                self.debug("Valid Cookie Found")
                request.environ['REMOTE_USER'] = session['username']
                return fn(*args, **kwargs)
            elif ticket:
                self.debug("Ticket: %s received" % ticket)
                status, user = self._validate(ticket)
                if status==TICKET_OK:
                    self.debug("Ticket OK")
                    session['username'] = user
                    session.save()

                    # Remove the query variables from uri
                    url = request.urlparts
                    new_url = (url[0],url[1],url[2],'',url[4])
                    redirect(urlunsplit(new_url))
                    #return fn(*args, **kwargs)
                else:
                    raise Exception("Ticket Validation FAILED!")
            self.debug("User not authenticated: redirecting to cas login page")
            self._do_login()
        return wrapper

    def require_user(self, users=None):
        """
        Decorator to permit access only to the given list of CAS-authenticated users.

        :Usage:
           from bottle_cas import client
           cas = client()

           @route('/foo')
           @cas.require
           @cas.require_user(['longb4'])
           def foo():

        :returns: A wrapped route that requires the authenticated user to be in the given access list
        :rtype: `function`
        """
        def required_user_decorator(fn):
            @wraps(fn)
            def wrapper(*args, **kwargs):
                current_user = request.environ.get('REMOTE_USER')
                valid_user = False
                if not current_user:
                    # The wrapped route probably doesn't have @cas.require above this decorator call
                    bottle.abort(403, "No user detected")
                if users:
                    if current_user in users:
                        valid_user = True
                    else:
                        message = "Permission denied: {} is not an authorized user.".format(current_user)
                if valid_user:
                    return fn(*args, **kwargs)
                else:
                    # User unauthorized
                    bottle.abort(401, message)
            return wrapper
        return required_user_decorator

    def logout(self, next = None):
        """
        Will Redirect a user to the CAS logout page

        :returns: Will not return
        :rtype: `None`
        """
        new_url = self.CAS_SERVER + self.CAS_LOGOUT_URL

        if next:
            next = '?url=' + urlencode(next)
            new_url = new_url + next
        session = request.environ['beaker.session']
        session.delete()
        #response.set_cookie(self._CAS_COOKIE, '', expires=0)
        self.debug("User logged out with request %s" % new_url)
        redirect(new_url)

    # A function to grab a xml tag. This isn't the best possible implementation but it works
    # It also doesn't require an external library
    def _parse_tag(self, str,tag):
        """
        Internal Function to parse a specific xml tag

        :Usage:
            _parse_tag(foo_string, "tag")

        :returns: the text contained within the tag specified
        :returns: `string`
        """
        tag1_pos1 = str.find("<" + tag)
        #  No tag found, return empty string.
        if tag1_pos1==-1: return ""
        tag1_pos2 = str.find(">",tag1_pos1)
        if tag1_pos2==-1: return ""
        tag2_pos1 = str.find("</" + tag,tag1_pos2)
        if tag2_pos1==-1: return ""
        return str[tag1_pos2+1:tag2_pos1].strip()

    # Validate the CAS ticket using CAS version 2
    def _validate(self, ticket):
        """
        Internal function to validate a CAS ticket

        :returns: ticket_status and username
        :rtype: `int` and `string`
        """
        url = request.urlparts
        newurl = urlunsplit((url[0],url[1],url[2],'',url[4]))
        params = { 'ticket': ticket, 'service': newurl }
        url_string = self.CAS_SERVER + "/cas/serviceValidate?" + urlencode(params)
        validate_resp = requests.get(url_string, verify=True)
        resp = validate_resp.text
        user = self._parse_tag(resp, "cas:user")

        if user=='':
            return TICKET_INVALID, ""
        else:
            return TICKET_OK, user

class CASMiddleware(SessionMiddleware):
    def __init__(self, app, cas_client):
        self.cas_client = cas_client
        SessionMiddleware.__init__(self, app, self.get_beaker_opts())

    def get_beaker_opts(self):
        cas_client = self.cas_client
        return  {
            'session.type': cas_client.BEAKER_TYPE,
            'session.data_dir': cas_client.BEAKER_DATA_DIR,
            'session.lock_dir': cas_client.BEAKER_LOCK_DIR,
            'session.cookie_expires': True,
            'session.secure': not cas_client.ALLOW_HTTP,
            'session.timeout': cas_client.TIMEOUT,
            'session.validate_key': cas_client.CAS_COOKIE + cas_client.SECRET,
            'session.encrypt_key': cas_client.SECRET,
            }

if __name__ == '__main__':
    cas = CASClient()
    app = bottle.app()
    from beaker.middleware import SessionMiddleware
    from ProxyMiddleware.ProxyMiddleware import ReverseProxied
    application = ReverseProxied(CASMiddleware(app))

    @route('/')
    def index():
        user = request.environ.get('REMOTE_USER') or 'default'
        resp =  """
            <a href="/thing">A page for authenticated clients</a>
            """
        return resp

    @route('/test')
    @cas.test_login
    def test():
        return request.environ.get('REMOTE_USER_STATUS')

    @route('/thing')
    @cas.require
    def thing():
        user = request.environ.get('REMOTE_USER')
        return "Hello, %s. This is a CAS client written in bottle\n <a href='logout'>Logout</a>" %user

    @route('/logout')
    def log_out():
        cas.logout('http://reddit.com/')
    run(app=application,host='localhost', port=8001)
