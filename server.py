#!/usr/local/bin/python
# -*- coding: utf-8 -*-

__copyright__ = 'Copyright 2011-2013 Hugo Osvaldo Barrera'

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse

import time
import cgi
import cgitb

import sys
import hashlib

import os
import mimetypes
mimetypes.init()


def quoteattr(s):
    qs = cgi.escape(s, 1)
    return '"%s"' % (qs,)

import openid

from openid.extensions import sreg
from openid.server import server
from openid.store.filestore import FileOpenIDStore
from openid.consumer import discover

class OpenIDHTTPServer(HTTPServer):
    """
    http server that contains a reference to an OpenID Server and
    knows its base URL.
    """
    def __init__(self, *args, **kwargs):
        HTTPServer.__init__(self, *args, **kwargs)

        self.server_name = "hugo.osvaldobarrera.com.ar"
        self.base_url = 'https://%s/' % (self.server_name,)

        self.openid = None
        self.approved = {}
        self.lastCheckIDRequest = {}

    def setOpenIDServer(self, oidserver):
        self.openid = oidserver


class ServerHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.user = None # FIXME deleteme
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)


    def do_GET(self):
        try:
            self.parsed_uri = urlparse(self.path)
            self.query = {}
            for k, v in cgi.parse_qsl(self.parsed_uri[4]):
                self.query[k] = v

            path = self.parsed_uri[2].lower()

            if path == '/':
                #self.showMainPage()
                self.showIdPage("hugo")
            elif path == '/openidserver':
                self.serverEndPoint(self.query)

            elif path.startswith('/id/'):
                self.showIdPage(path)
            elif path.startswith('/yadis/'):
                self.showYadis(path[7:])
            elif path == '/serveryadis':
                self.showServerYadis()
            elif path.startswith("/static/"):
                self.serve_static(path[8:])
            else:
                self.send_response(404)
                self.end_headers()

        except (KeyboardInterrupt, SystemExit):
            raise
        # except:
        #     self.send_response(500)
        #     self.send_header('Content-type', 'text/html')
        #     self.end_headers()
        #     self.wfile.write(cgitb.html(sys.exc_info(), context=10))
        #     print("---")
        #     print(cgitb.html(sys.exc_info(), context=10))

    def serve_static(self, filename):
        filepath = os.path.join("static", filename)
        f = open(filepath)
        extension = os.path.splitext(filepath)[1]
        self.send_response(200)
        self.send_header('Content-type', mimetypes.types_map[extension])
        self.end_headers()
        self.wfile.write(f.read())
        f.close()

    def do_POST(self):
        try:
            self.parsed_uri = urlparse(self.path)

            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)

            self.query = {}
            for k, v in cgi.parse_qsl(post_data):
                self.query[k] = v

            path = self.parsed_uri[2]
            if path == '/openidserver':
                self.serverEndPoint(self.query)

            elif path == '/allow':
                self.handleAllow(self.query)
            else:
                self.send_response(404)
                self.end_headers()

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(cgitb.html(sys.exc_info(), context=10))

    def handleAllow(self, query):
        if 'pass' in self.query:
            pwd_hash = hashlib.md5(self.query['pass']).hexdigest()
            # HARDCODED PASSWORD LOCATION
            if pwd_hash == 'bff27503ad48a4580d3ad10606400773':
                request = self.server.lastCheckIDRequest.get(self.user)

                if 'yes' in query :

                    if request.idSelect():
                        identity = self.server.base_url
                    else:
                        identity = request.identity

                    trust_root = request.trust_root

                    response = self.approved(request, identity)

                elif 'no' in query:
                    response = request.answer(False)

                else:
                    assert False, 'strange allow post.  %r' % (query,)
                self.displayResponse(response)
            else:
                self.showPage(403,'Bad password',err='Bad password')
        else:
            self.showPage(403,'No password specified',err='No password specified')

    def isAuthorized(self, identity_url, trust_root):

        key = (identity_url, trust_root)
        return self.server.approved.get(key) is not None

    def serverEndPoint(self, query):
        try:
            request = self.server.openid.decodeRequest(query)
        except server.ProtocolError, why:
            self.displayResponse(why)
            return

        if request is None:
            # Display text indicating that this is an endpoint.
            self.showAboutPage()
            return

        if request.mode in ["checkid_immediate", "checkid_setup"]:
            self.handleCheckIDRequest(request)
        else:
            response = self.server.openid.handleRequest(request)
            self.displayResponse(response)

    def addSRegResponse(self, request, response):
        sreg_req = sreg.SRegRequest.fromOpenIDRequest(request)

        # In a real application, this data would be user-specific,
        # and the user should be asked for permission to release
        # it.
        sreg_data = {
            'nickname':self.user
            }

        sreg_resp = sreg.SRegResponse.extractResponse(sreg_req, sreg_data)
        response.addExtension(sreg_resp)

    def approved(self, request, identifier=None):
        response = request.answer(True, identity=identifier)
        self.addSRegResponse(request, response)
        return response

    def handleCheckIDRequest(self, request):
        is_authorized = self.isAuthorized(request.identity, request.trust_root)
        if is_authorized:
            response = self.approved(request)
            self.displayResponse(response)
        elif request.immediate:
            response = request.answer(False)
            self.displayResponse(response)
        else:
            self.server.lastCheckIDRequest[self.user] = request
            self.showDecidePage(request)

    def displayResponse(self, response):
        try:
            webresponse = self.server.openid.encodeResponse(response)
        except server.EncodingError, why:
            text = why.response.encodeToKVForm()
            self.showErrorPage('<pre>%s</pre>' % cgi.escape(text))
            return

        self.send_response(webresponse.code)
        for header, value in webresponse.headers.iteritems():
            self.send_header(header, value)
        self.end_headers()

        if webresponse.body:
            self.wfile.write(webresponse.body)

    def redirect(self, url):
        self.send_response(302)
        self.send_header('Location', url)

        self.end_headers()

    def showAboutPage(self):
        endpoint_url = self.server.base_url + 'openidserver'

        def link(url):
            url_attr = quoteattr(url)
            url_text = cgi.escape(url)
            return '<a href=%s><code>%s</code></a>' % (url_attr, url_text)

        def term(url, text):
            return '<dt>%s</dt><dd>%s</dd>' % (link(url), text)

        resources = [
            (self.server.base_url, "This example server's home page"),
            ('http://www.openidenabled.com/',
             'An OpenID community Web site, home of this library'),
            ('http://www.openid.net/', 'the official OpenID Web site'),
            ]

        resource_markup = ''.join([term(url, text) for url, text in resources])

        self.showPage(200, 'This is an OpenID server', msg="""\
        <p>%s is an OpenID server endpoint.<p>
        <p>For more information about OpenID, see:</p>
        <dl>
        %s
        </dl>
        """ % (link(endpoint_url), resource_markup,))

    def showErrorPage(self, error_message):
        self.showPage(400, 'Error Processing Request', err='<p>%s</p>' % error_message)

    def showDecidePage(self, request):

        fdata = {
                'identity': self.server.base_url,
                'trust_root': request.trust_root,
                }

        # msg = '''\
        # <p>A new site has asked to confirm your identity.  If you
        # approve, the site represented by the trust root below will
        # be told that you control identity URL listed below. (If
        # you are using a delegated identity, the site will take
        # care of reversing the delegation on its own.)</p>'''

        form = '''\
        <dl>
          <dt>Identity</dt>
          <dd>%(identity)s</dd>
        </dl>
        <dl>
          <dt>Trust Root</dt>
          <dd>%(trust_root)s</dd>
        </dl>
        <form method="POST" action="/allow">
          <input type=password name="pass" value="" /><br />
          <p>Allow this authentication to proceed?</p>
          <button type="submit" class="btn btn-primary" name="yes" value="yes" />Yes</button>
          <button type="submit" class="btn" name="no" value="no" />No</button>
        </form>''' % fdata

        self.showPage(200, 'Approve OpenID request?', form=form) #msg=msg,

    def showIdPage(self, path):
        link_tag = '<link rel="openid.server" href="%sopenidserver">' %\
              self.server.base_url
        yadis_loc_tag = '<meta http-equiv="x-xrds-location" content="%s">'%\
            (self.server.base_url+'yadis/'+path[4:])
        disco_tags = link_tag + yadis_loc_tag
        ident = self.server.base_url #+ path[0:]

        approved_trust_roots = []
        for (aident, trust_root) in self.server.approved.keys():
            if aident == ident:
                trs = '<li><tt>%s</tt></li>\n' % cgi.escape(trust_root)
                approved_trust_roots.append(trs)

        if approved_trust_roots:
            prepend = '<p>Approved trust roots:</p>\n<ul>\n'
            approved_trust_roots.insert(0, prepend)
            approved_trust_roots.append('</ul>\n')
            msg = ''.join(approved_trust_roots)
        else:
            msg = ''

        self.showPage(200, 'An Identity Page', head_extras=disco_tags, msg='''\
        <p>This is an identity page for %s.</p>
        %s
        ''' % (ident, msg))

    def showYadis(self, user):
        self.send_response(200)
        self.send_header('Content-type', 'application/xrds+xml')
        self.end_headers()

        endpoint_url = self.server.base_url + 'openidserver'
        user_url = self.server.base_url
        self.wfile.write("""\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://$xrds"
    xmlns="xri://$xrd*($v*2.0)">
  <XRD>

    <Service priority="0">
      <Type>%s</Type>
      <Type>%s</Type>
      <URI>%s</URI>
      <LocalID>%s</LocalID>
    </Service>

  </XRD>
</xrds:XRDS>
"""%(discover.OPENID_2_0_TYPE, discover.OPENID_1_0_TYPE,
     endpoint_url, user_url))

    def showServerYadis(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/xrds+xml')
        self.end_headers()

        endpoint_url = self.server.base_url + 'openidserver'
        self.wfile.write("""\
<?xml version="1.0" encoding="UTF-8"?>
<xrds:XRDS
    xmlns:xrds="xri://$xrds"
    xmlns="xri://$xrd*($v*2.0)">
  <XRD>

    <Service priority="0">
      <Type>%s</Type>
      <URI>%s</URI>
    </Service>

  </XRD>
</xrds:XRDS>
"""%(discover.OPENID_IDP_2_0_TYPE, endpoint_url,))

    def showMainPage(self):
        yadis_tag = '<meta http-equiv="x-xrds-location" content="%s">'%\
            (self.server.base_url + 'serveryadis')
        if self.user:
            openid_url = self.server.base_url
            user_message = """\
            <p>You are logged in as %s. Your OpenID identity URL is
            <tt><a href=%s>%s</a></tt>. Enter that URL at an OpenID
            consumer log in using this server.</p>
            """ % (self.user, quoteattr(openid_url), openid_url)
        else:
            user_message = "<p>You are not <a href='/login'>logged in</a>.</p>"

        self.showPage(200, 'Main Page', head_extras = yadis_tag, msg='''\
        <p>This is a simple OpenID server implemented using the <a
        href="http://openid.schtuff.com/">Python OpenID
        library</a>.</p>

        %s

        <p>The URL for this server is <a href=%s><tt>%s</tt></a>.</p>
        ''' % (user_message, quoteattr(self.server.base_url), self.server.base_url))

    def showPage(self, response_code, title,
                 head_extras='', msg=None, err=None, form=None):

        body = ''

        if err is not None:
            body +=  '<p class="text-error">{}</p>'.format(err)

        if msg is not None:
            body += '<p class="info">{}</div>'.format(msg)

        if form is not None:
            body += '<div class="form">{}</div>'.format(form)

        contents = {
            'title': 'Python OpenID Server - ' + title,
            'head_extras': head_extras,
            'body': body,
            }

        self.send_response(response_code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        self.wfile.write('''
<!DOCTYPE html>
<html>
  <head>
    <title>{title}</title>
    <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
    {head_extras}
  <link href="//netdna.bootstrapcdn.com/twitter-bootstrap/2.3.2/css/bootstrap-combined.min.css" rel="stylesheet">
  <link href="static/openid.css" rel="stylesheet">

  </head>
  <body>
    <h1>Q&D OpenID Server</h1>
{body}
  </body>
</html>
'''.format(**contents))


def main(host, port, data_path):
    addr = (host, port)
    httpserver = OpenIDHTTPServer(addr, ServerHandler)

    # Instantiate OpenID consumer store and OpenID consumer.  If you
    # were connecting to a database, you would create the database
    # connection and instantiate an appropriate store here.
    store = FileOpenIDStore(data_path)
    oidserver = server.Server(store, httpserver.base_url + 'openidserver')

    httpserver.setOpenIDServer(oidserver)

    print("Server running at:")
    print(httpserver.base_url)
    httpserver.serve_forever()

if __name__ == '__main__':
    host = 'localhost'
    data_path = 'sstore'
    port = 8999

    main(host, port, data_path)
