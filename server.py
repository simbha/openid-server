#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# Copyright (c) 2012 Hugo Osvaldo Barrera <hugo@osvaldobarrera.com.ar>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

__copyright__ = 'Copyright 2011-2013 Hugo Osvaldo Barrera'

from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from urlparse import urlparse
from jinja2 import Environment, FileSystemLoader

import cgi

import sys
import hashlib

import os
import mimetypes
mimetypes.init()

import uuid
import Cookie


def quoteattr(s):
    qs = cgi.escape(s, 1)
    return '"{}"'.format(qs)

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
        self.base_url = 'https://{}/'.format(self.server_name)

        self.openid = None
        self.approved = {}
        self.recentAllowRequests = {}

        # Preload templates
        env = Environment(loader=FileSystemLoader('templates'))

        self.base_template = env.get_template('base.html')
        self.decide_template = env.get_template('decide.html')
        self.home_template = env.get_template('home.html')

        self.yadis_template = env.get_template('yadis.xml')
        self.yadis_server_template = env.get_template('yadis_server.xml')

    def setOpenIDServer(self, oidserver):
        self.openid = oidserver


class ServerHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        self.user = "Hugo"  # FIXME deleteme
        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def do_GET(self):
        try:
            self.parsed_uri = urlparse(self.path)
            self.query = {}
            for k, v in cgi.parse_qsl(self.parsed_uri[4]):
                self.query[k] = v

            path = self.parsed_uri[2].lower()

            if path == '/':
                self.showIdPage()
            elif path == '/openidserver':
                self.serverEndPoint(self.query)

            elif path.startswith('/yadis'):
                self.showYadis()
            elif path == '/serveryadis':
                self.showServerYadis()
            elif path.startswith("/static/"):
                self.serve_static(path[8:])
            else:
                self.send_response(404)
                self.end_headers()

        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.send_error(500)
            raise

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
            self.send_error(500)
            raise

    def serve_static(self, filename):
        """
        Serve static files from the static/ directory.

        This could be proxied by nginx for production, but it's nice-to-have
        for development.
        """

        filepath = os.path.join("static", filename)
        f = open(filepath)
        extension = os.path.splitext(filepath)[1]
        self.send_response(200)
        self.send_header('Content-type', mimetypes.types_map[extension])
        self.end_headers()
        self.wfile.write(f.read())
        f.close()

    def handleAllow(self, query):
        try:
            c = Cookie.SimpleCookie(self.headers["Cookie"])
            visitor_id = c["visitor_id"].value
        except KeyError:
            self.showPage(400, err="Bad cookie.")
            return

        request = self.server.recentAllowRequests[visitor_id]

        if 'yes' in query:
            if 'pass' in self.query:
                pwd_hash = hashlib.md5(self.query['pass']).hexdigest()
                # HARDCODED PASSWORD LOCATION
                if pwd_hash == 'bff27503ad48a4580d3ad10606400773':
                    trust_root = request.trust_root
                    response = self.approved(request)
                    self.displayResponse(response)
                else:
                    self.showPage(403, err='Bad password.')
            else:
                self.showPage(403, err='No password specified.')
        elif 'no' in query:
            response = request.answer(False)
        else:
            self.showPage(400, err="No action (what button did you click!?).")

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
            self.send_response(302)
            self.send_header('Location', self.server.base_url)
            self.end_headers()
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
        sreg_data = {'nickname': self.user}

        sreg_resp = sreg.SRegResponse.extractResponse(sreg_req, sreg_data)
        response.addExtension(sreg_resp)

    def approved(self, request):
        response = request.answer(True, identity=self.server.base_url)
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
            self.showDecidePage(request)

    def displayResponse(self, response):
        try:
            webresponse = self.server.openid.encodeResponse(response)
        except server.EncodingError, why:
            text = why.response.encodeToKVForm()
            self.showErrorPage('<pre>{}</pre>'.format(cgi.escape(text)))
            return

        self.send_response(webresponse.code)
        for header, value in webresponse.headers.iteritems():
            self.send_header(header, value)
        self.end_headers()

        if webresponse.body:
            self.wfile.write(webresponse.body)

    def showErrorPage(self, error_message):
        self.showPage(400, err='<p>{}</p>'.format(error_message))

    def showDecidePage(self, request):

        visitor_id = str(uuid.uuid4())
        self.server.recentAllowRequests[visitor_id] = request

        page = self.server.decide_template.\
            render(identity = self.server.base_url,
                   trust_root = request.trust_root)

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header("Set-Cookie", "visitor_id={}".format(visitor_id))
        self.end_headers()

        self.wfile.write(page)

    def showIdPage(self):
        link_tag = '<link rel="openid.server" href="%sopenidserver">' %\
            self.server.base_url
        yadis_loc_tag = '<meta http-equiv="x-xrds-location" content="%s">' %\
            (self.server.base_url+'yadis')
        head_tags = link_tag + yadis_loc_tag
        ident = self.server.base_url

        page = self.server.home_template.render(url=self.server.base_url,
                                                head_extras=head_tags)

        self.return_page(page)

    def showYadis(self, user="hugo"):
        self.send_response(200)
        self.send_header('Content-type', 'application/xrds+xml')
        self.end_headers()

        endpoint_url = self.server.base_url + 'openidserver'
        user_url = self.server.base_url

        page = self.server.yadis_template.render(type1=discover.OPENID_2_0_TYPE,
                                                 type2=discover.OPENID_1_0_TYPE,
                                                 uri = endpoint_url,
                                                 local_id = user_url)

        self.wfile.write(page)

    def showServerYadis(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/xrds+xml')
        self.end_headers()

        endpoint_url = self.server.base_url + 'openidserver'

        page = self.server.yadis_template.render(type=discover.OPENID_IDP_2_0_TYPE,
                                                 uri = endpoint_url)

        self.wfile.write(page)

    def showPage(self, response_code, head_extras='', msg=None, err=None):

        contents = {
            'err': err,
            'msg': msg,
            'head_extras': head_extras,
        }
        page = self.server.base_template.render(**contents)

        self.return_page(page, response_code)

    def return_page(self, page, status_code=200):
        self.send_response(status_code)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        self.wfile.write(page)


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
