#!/usr/bin/python

# ###############################
# Open Flag Server: flags.py
#
# Copyright (c) 2015 Jason Gillam
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this files except in compliance with the License.
# You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the License for the specific language governing permissions and
# limitations under the License.
################################
import os
import re
import cherrypy
import argparse
import sqlite3
import hashlib
import json
from datetime import datetime

dbfile = 'participants.db'
flagids = {}
hashes = {}
handleregex = re.compile('^[a-z0-9A-Z]{3,24}$')
leaders = []
special_files = {}


def secureheaders():
    headers = cherrypy.response.headers
    headers['X-Frame-Options'] = 'DENY'
    headers['X-XSS-Protection'] = '1; mode=block'
    # headers['Content-Security-Policy'] = "default-src='self'"


def error_page_404(status, message, traceback, version):
    return "These are not the droids you are looking for..."


# def handle_error():
#     cherrypy.response.status = 500
#     cherrypy.response.body = ["<html><body>Some error occurred but I don't feel like handling it...</body></html>"]

def init_db():
    if os.path.isfile(dbfile):
        print 'Using existing db file.  To start fresh, remove %s.' % dbfile
    else:
        conn = sqlite3.connect(dbfile)
        c = conn.cursor()
        c.execute('CREATE TABLE users (handle text, passwdhash text)')
        c.execute('CREATE TABLE flags (handle text, flagid text, time text)')
        conn.commit()
        conn.close()
        print('Db initialized in %s' % dbfile)


def init_flags(flagfile):
    print "Loading flag config from: %s" % flagfile
    f = open(flagfile)
    flagconfig = json.load(f)
    f.close()
    for flag in flagconfig["flags"]:
        flaginfo = {"id": flag["id"], "value": flag["value"]}
        hashes[flag["hash"]] = flaginfo
        flagids[flag["id"]] = flag["hash"]
    print "%i flags loaded." % len(flagids)
    if "help" in flagconfig:
        special_files["help"] = flagconfig["help"]
    else:
        special_files["help"] = "example-help.html";
    print "Help file assigned to: %s" % special_files["help"]


def update_leaders():
    conn = sqlite3.connect(dbfile)
    c = conn.cursor()
    c.execute('SELECT * FROM flags')
    rows = c.fetchall()

    unsortedleaders = {}
    for row in rows:
        if row[0] not in unsortedleaders:
            entry = {'flags': 0, 'score': 0}
            unsortedleaders[row[0]] = entry
        unsortedleaders[row[0]]['flags'] += 1
        hash = flagids[row[1]]
        value = hashes[hash]['value']
        unsortedleaders[row[0]]['score'] += value

    scoreboard = []
    for handle in unsortedleaders:
        scoreboard.append((handle, unsortedleaders[handle]['flags'], unsortedleaders[handle]['score']))
        scoreboard = sorted(scoreboard, key=lambda score: score[2], reverse=True)

    del leaders[:]
    for score in scoreboard:
        leaders.append({'handle': score[0], 'flags': score[1], 'score': score[2]})


class FlagServer(object):
    # _cp_config = {'request.error_response': handle_error}

    @cherrypy.expose
    def index(self, handle='', password=''):
        if 'handle' not in cherrypy.session:
            if handle != '' and password != '':
                conn = sqlite3.connect(dbfile)
                c = conn.cursor()
                c.execute('SELECT handle FROM users where handle = ? and passwdhash = ?',
                          (handle, hashlib.sha256(handle + password).hexdigest()))
                if len(c.fetchall()) == 1:
                    print 'Successful login: %s' % handle
                    cherrypy.session['handle'] = handle
                    conn.commit()
                    conn.close()
                    return file('main.html')
                else:
                    print 'Failed login: %s' % handle
                    conn.commit()
                    conn.close()
                    return 'Login failed.  <a href="/login">Try again</a>'
            else:
                return file('main.html')
        else:
            return file('main.html')

    @cherrypy.expose
    def login(self):
        if 'handle' not in cherrypy.session or cherrypy.session['handle'] == '':
            return file('login.html')
        else:
            return file('main.html')

    @cherrypy.expose
    def logout(self):
        cherrypy.lib.sessions.expire()
        return file('main.html')

    @cherrypy.expose
    def help(self):
        return file(special_files["help"])

    @cherrypy.expose
    def register(self, handle='', password='', password2=''):
        print 'Registration request for %s received: ' % handle
        if handle == '' or password == '':
            return file('register.html')
        elif password != password2:
            return 'Passwords do not match.  <a href="/register">Try again</a>.'
        else:
            conn = sqlite3.connect(dbfile)
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE handle = ?', (handle,))
            if not handleregex.match(handle):
                return 'Error: Handle / Name can only be 3-24 alpha-numeric characters. ' \
                       '<a href="/register">Try another</a>.'
            elif len(c.fetchall()) == 0:
                newuser = (handle, hashlib.sha256(handle + password).hexdigest())
                c.execute('INSERT INTO users VALUES(?, ?)', newuser)
                conn.commit()
                conn.close()
                return file('login.html')
            else:
                conn.commit()
                conn.close()
                return 'That handle is already taken.  <a href="/register">Try another</a>.'

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def initui(self):
        data = {}
        if 'handle' in cherrypy.session:
            data["handle"] = cherrypy.session["handle"]
        return data

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def submitflag(self, flag=''):
        if 'handle' in cherrypy.session and flag in hashes:
            conn = sqlite3.connect(dbfile)
            c = conn.cursor()
            c.execute('SELECT * FROM flags where handle = ? and flagid = ?',
                      (cherrypy.session['handle'], hashes[flag]['id']))
            if len(c.fetchall()) == 0:
                newflag = (cherrypy.session['handle'], hashes[flag]['id'], datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                c.execute('INSERT INTO flags VALUES(?, ?, ?)', newflag)
                conn.commit()
                conn.close()
                print "*** Flag found by " + cherrypy.session['handle'] + ": " + hashes[flag]['id']
                update_leaders()
                return hashes[flag]
            else:
                conn.commit()
                conn.close()
                return {}
        else:
            return {}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def listflags(self):
        if 'handle' in cherrypy.session:
            conn = sqlite3.connect(dbfile)
            c = conn.cursor()
            c.execute('SELECT * FROM flags where handle = ?', (cherrypy.session['handle'],))
            rows = c.fetchall()
            data = []
            for row in rows:
                flag = {}
                flag['id'] = row[1]
                flag['time'] = row[2]
                data.append(flag)
            return data
        else:
            return []


    @cherrypy.expose
    @cherrypy.tools.json_out()
    def listleaders(self):
        return leaders


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Runs a simple scoring server for submitting flags in a CTF "
                                                 "(capture the flag)")
    parser.add_argument('-p', '--port', default='8080', help='The listening port for the flag server.')
    parser.add_argument('flags', help='The flag configuration file.  See example.flags for example.')
    args = parser.parse_args()
    init_flags(args.flags)

    cherrypy.tools.secureheaders = cherrypy.Tool('before_finalize', secureheaders, priority=60)
    app_path = os.path.abspath(os.getcwd())
    conf = {
        '/': {
            'tools.sessions.on': True,
            # 'tools.sessions.secure': True,
            'tools.sessions.httponly': True,
            'tools.secureheaders.on': True,
            'tools.staticdir.root': app_path
        },
        '/static': {
            'tools.staticdir.on': True,
            'tools.staticdir.dir': 'static'
        },
        '/favicon.ico': {
            'tools.staticfile.on': True,
            'tools.staticfile.filename': app_path + '/static/favicon.ico'
        }
    }

    cherrypy.config.update({'server.socket_port': int(args.port),
                            'server.socket_host': '0.0.0.0',
                            'error_page.404': error_page_404})
    init_db()
    update_leaders()
    cherrypy.quickstart(FlagServer(), '/', conf)