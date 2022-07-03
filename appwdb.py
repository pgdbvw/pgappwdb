# -*- coding: utf-8 -*-
###############################################################################
# This file is part of Postgres Application Server
# Copyright (c) 2020-2021 Alexey Maslyukov
# Contact:  mao50mao@gmail.com
#
# GNU General Public License Usage
# This file may be used under the terms of the GNU General Public License
# version 3.0 as published by the Free Software Foundation and appearing in the
# file LICENSE included in the packaging of this file.
#
# Please review the following information to ensure the GNU General Public
# License version 3.0
# requirements will be met: http://www.gnu.org/copyleft/gpl.html.
#
###############################################################################

import wdbstate  # import breakpoints, sockets, syncwebsockets, websockets
import wdbstreams  # import handle_connection
import pbipwdb
import base64
import threading
import asyncio
import subprocess
import re
#from transliterate import translit
#import argparse
import tornado.web
from tornado.options import options
from tornado.httpclient import AsyncHTTPClient
from tornado.netutil import add_accept_handler, bind_sockets
#import psycopg2

#import pandas as pd
#from pandas.api.types import is_numeric_dtype
#import numpy as np

import os
import platform
import sys
import json
import datetime
import time
from logging import ERROR, DEBUG, INFO, WARNING, getLogger
#import logging
from uuid import uuid4, UUID


import appoptions

__author__    = "Alexey Maslyukov (mao50mao@gmail.com)"
__copyright__ = "Copyright (c) 2022 Alexey Maslyukov"
__license__   = "GPL v3"
__version__   = "1.0-0 beta"

log = getLogger('pgappsrv')


def init(app):
    app.add_handlers(r'.*', [(r"{}".format(r"/appwdb/cmd/prog"), CmdHandler)])
    #app.add_handlers(r'.*', [(r"{}".format(r"/appwdb/cmd"), CmdHandler)])
    #app.add_handlers(r'.*', [(r"{}".format(r"/appdebug/(.+)"), WebSocketHandler)])
    
    """if options.wdbhost.lower() == 'localhost' or options.wdbhost == '127.0.0.1':
        log.info('Start WDB server')
        log.info('[WDB] Binding sockets: %d' % options.wdbport)
        sockets = bind_sockets(options.wdbport)
        for sck in sockets:
            log.debug('[WDB] Accepting debug sessions from %s' % (str(sck or '')))
            add_accept_handler(sck, wdbstreams.handle_connection)"""

    return __version__

def json_serial(o):
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.isoformat()
    elif isinstance(o, UUID):
        return str(o)

def row2obj(row, cur):
    """Convert a SQL row to an object supporting dict and attribute access."""
    obj = tornado.util.ObjectDict()
    for val, desc in zip(row, cur.description):
        obj[desc.name] = val
    return obj

from itertools import (takewhile,repeat)

def rawincount(filename):
    try:
        f = open(filename, 'rb')
        bufgen = takewhile(lambda x: x, (f.raw.read(1024*1024) for _ in repeat(None)))
        return sum( buf.count(b'\n') for buf in bufgen )
    except Exception as e:
        return None

class AppSrvError(Exception):
    pass


class NoResultError(Exception):
    pass


class BaseHandler(tornado.web.RequestHandler):

    def set_default_headers(self):
        #log.info("---- BaseHandler SetDefaultHeader")
        self.set_header("Access-Control-Allow-Origin", "*")
        #self.set_header("Access-Control-Allow-Headers", "x-requested-with")
        self.set_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.set_header("Access-Control-Allow-Headers", "referer,user-agent,content-type,x-requested-with,x-xsrftoken,x-browser,x-browser-version")
        #self.set_header("Access-Control-Allow-Headers", "*")

    async def options(self):
        self.set_status(204)
        self.finish()

    def check_xsrf_cookie(self):
        tok = self.request.headers.get('X-XSRFToken')
        if tok == None:
            tok = self.get_argument('xsrf', None)
        log.debug('----Check----')
        log.debug('Token cookie: %s', tok)
        #log.debug(self.application.authTokens)
        if tok in self.application.authTokens:
            if datetime.datetime.utcnow() > self.application.authTokens[tok]['exp']:
                self.application.authTokens.pop(tok)
                self.set_header("X-XSRFToken", self.xsrf_token)
                self.application.loginTokens[self.xsrf_token.decode('ascii')] = datetime.datetime.utcnow()+datetime.timedelta(minutes=5)
                raise tornado.web.HTTPError(403, "Authorization time expired")
            return
        else:
            self.clear_cookie("user")
            self.set_header("X-XSRFToken", self.xsrf_token)
            self.application.loginTokens[self.xsrf_token.decode(
                'ascii')] = datetime.datetime.utcnow()+datetime.timedelta(minutes=5)
            #self.set_cookie("_xsrf", self.xsrf_token, expires_days=1)
            raise tornado.web.HTTPError(403, "XSRF cookie does not match")

    async def execute(self, stmt, *args):
        if self.application.db == None:
            raise AppSrvError
        with (await self.application.db.cursor()) as cur:
            await cur.execute(stmt, args)

    async def query(self, stmt, *args):
        if self.application.db == None:
            raise AppSrvError
        with (await self.application.db.cursor()) as cur:
            await cur.execute(stmt, args)
            return [row2obj(row, cur) for row in await cur.fetchall()]

    async def queryone(self, stmt, *args):
        results = await self.query(stmt, *args)
        if len(results) == 0:
            raise NoResultError()
        elif len(results) > 1:
            raise ValueError("Expected 1 result, got %d" % len(results))
        return results[0]

    async def prepare(self):
        #log.debug('URI:  "%s"', self.request.uri)
        #log.debug('Method:  "%s"', self.request.method)
        #log.debug('Headers: "%s"', self.request.headers)
        #log.debug('Body:    "%s"', self.request.body)
        tok = self.request.headers.get('X-XSRFToken')
        if tok == None:
            tok = self.get_argument('xsrf', None)
        if self.application.db != None:
            try:
                sess_uuid = self.application.authTokens[tok]['uuid']
                if sess_uuid:
                    try:
                        self.current_sess = await self.queryone('SELECT * FROM "'+str(self.application.authTokens[tok]['system']) +
                                                                '".appsession WHERE sessid = %s', sess_uuid)
                    except Exception as e:
                        self.current_sess = None
            except Exception as e:
                self.current_sess = None

class CmdHandler(BaseHandler):
    # @tornado.web.authenticated
    async def post(self):
        tok = self.request.headers.get('X-XSRFToken')
        log.debug('%s:>>> /cmd/post', tok)
        log.debug('Body:    "%s"', self.request.body)
        sysid = self.application.authTokens[tok]['system']
        uuid = self.application.authTokens[tok]['uuid']
        full_cmd = json.loads(self.request.body.decode('UTF-8'))
        cmd = full_cmd['cmd']
        if 'progid' in full_cmd['values']:
            progid = full_cmd['values']['progid']
        else:
            progid = None
        ret = {}
        if cmd == 'activate':
            if 'wdb' in self.application.authTokens[tok]:
                if self.application.authTokens[tok]['wdb'] != None:
                    if 'dbg' in self.application.authTokens[tok]['wdb']:
                        self.application.authTokens[tok]['wdb']['dbg'].stop_trace()
                        self.application.authTokens[tok]['wdb'].pop('dbg')
                    wdbuuid = self.application.authTokens[tok]['wdb']['uuid']
                    if wdbuuid in wdbstate.websockets.uuids:
                        log.warning(
                            'Websocket already opened for %s. Closing previous one'
                            % wdbuuid
                        )
                        wdbstate.websockets.send(wdbuuid, 'Die')
                        wdbstate.websockets.close(wdbuuid)
            app_temp = os.path.join(os.path.abspath(self.application.options.app_pyc), self.application.options.app_temp)
            fname = os.path.join(os.path.abspath(app_temp), str(progid or '') +'.py')
            wdbuuid = str(uuid4())
            wdbstate.nbrsockets.add(wdbuuid, None) #proc)
            self.application.authTokens[tok]['wdb'] = {
                'uuid': wdbuuid,
                'pid': os.getpid(),
                'fname': fname,
                'mname': progid
            }
            ret['ret'] = {}
            ret['ret']['code'] = 0
            ret['ret']['stdout'] = ''
            ret['ret']['stderr'] = ''
            ret['ret']['pid'] = os.getpid() #proc.pid
            ret['ret']['uuid'] = wdbuuid
            ret['ret']['fname'] = fname
            log.debug('..!Debugger Activated!..')
        elif cmd == 'deactivate':
            if 'wdb' in self.application.authTokens[tok]:
                if self.application.authTokens[tok]['wdb'] != None:
                    if 'dbg' in self.application.authTokens[tok]['wdb']:
                        self.application.authTokens[tok]['wdb']['dbg'].stop_trace()
                    wdbuuid = self.application.authTokens[tok]['wdb']['uuid']
                    if wdbuuid in wdbstate.websockets.uuids:
                        wdbstate.websockets.send(wdbuuid, 'Die')
                        wdbstate.websockets.close(wdbuuid)
                    log.debug('...Debugger Deactivated...')
        elif cmd == 'GET':
            cmdd = {
                'cmd': 'GETDDICREC',
                'objtyp': 'program',
                'keyfld': 'progname',
                'id': progid
            }
            try:
                ret = await self.queryone('SELECT * FROM "'+ sysid + '".cmd_ddic(%s,%s::json)',uuid,json.dumps(cmdd, default=json_serial))    
                if ret['cmd_ddic'] != None:
                    data = {}
                    data['records'] = []
                    data['records'].append({
                        'ProgID': progid,
                        'src': base64.b64decode(bytes(ret['cmd_ddic']['data']['ddic_programl']['progdefb64'], 'UTF-8')).decode('UTF-8')
                    })
                    #ret['data'] = base64.b64decode(bytes(ret['cmd_ddic']['data']['ddic_programl']['progdefb64'], 'UTF-8')).decode('UTF-8')
                    ret['data'] = json.dumps(data, default=json_serial)
                else:
                    ret['__$isError'] = True
                    ret['msg'] = 'Cmd DDic Error'
            except Exception as ex:
                ret['msg'] = str(ex)
                ret['__$isError'] = True
        else:
            ret['__$isError'] = True
            ret['msg'] = 'Empty return'

        self.write(json.dumps(ret))
        self.set_status(200)


class EntryModule(tornado.web.UIModule):
    def render(self, entry):
        return self.render_string("modules/entry.html", entry=entry)
