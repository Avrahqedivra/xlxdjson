#!/usr/bin/env python3
#
###############################################################################
#   Copyright (C) 2022 Jean-Michel Cohen, F4JDN <f4jdn@outlook.fr>
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program; if not, write to the Free Software Foundation,
#   Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301  USA

# Standard modules
from fileinput import close
import json
from ssl import OPENSSL_VERSION_NUMBER
import xmltodict
import logging
import time as ptime
# import datetime
import base64
import urllib
import platform
import os
import binascii
import sys
import socket
import threading

from subprocess import CalledProcessError

# Twisted modules
from twisted.internet import reactor, endpoints, task, defer
from twisted.protocols.basic import FileSender

from twisted.web import http, server
from twisted.web.server import Session, Site
from twisted.web.resource import Resource, NoResource

from twisted.python.url import URL
from twisted.python.components import registerAdapter

from zope.interface import Interface, Attribute, implementer

# Autobahn provides websocket service under Twisted
from autobahn.twisted.websocket import WebSocketServerProtocol, WebSocketServerFactory
from autobahn.websocket.compress import *

# Specific functions to import from standard modules
from time import time
from pickle import loads

# Configuration variables and constants
from config import *

LOGINFO = False

# Configuration variables and constants
from config import *

# https://stackoverflow.com/questions/182197/how-do-i-watch-a-file-for-changes

CONFIG              = {}
CTABLEJ             = ""
MESSAGEJ            = []
LISTENERSJ          = []
BUTTONBAR_HTML      = ""

reflector           = []
modules             = []
nodes               = []
stations            = []

__signals = { "shutdown": False }

def xmltojson():
  global _nblines

  with open(LOG_PATH + 'xlxdfixed.xml', 'r') as infile:
    try:
        dict_data = xmltodict.parse(infile.read())
    except:
        pass

    with open(LOG_PATH + "xlxd.json", 'w+') as outfile:
      json.dump(dict_data, outfile, indent=4)

def ireplace(old, new, text):
    idx = 0
    while idx < len(text):
        index_l = text.lower().find(old.lower(), idx)
        if index_l == -1:
            return text
        text = text[:index_l] + new + text[index_l + len(old):]
        idx = index_l + len(new) 
    return text
    
def createLogTableJson():
  global MESSAGEJ

  with open(XLXDLOG_FILE, 'r') as file:
    lines = file.readlines()
    reflector = ""

    xmlfixed = ""

    # Strips the newline character
    for line in lines:
      try:
        line = line.strip()

        if line.startswith("<XLX") and reflector == "":
            reflector = line[1:7]

        line = line.replace('<STATION>', '<Station>').replace('</STATION>', '</Station>') \
            .replace('<NODE>', '<Nodes>').replace('</NODE>', '</Nodes>') \
            .replace('<PEER>', '<Peer>').replace('</PEER>', '</Peer>') \
            .replace('<Via peer>', '<ViaPeer>').replace('</Via peer>', '</ViaPeer>') \
            .replace('<Via node>', '<ViaNode>').replace('</Via node>', '</ViaNode>') \
            .replace('<On module>', '<OnModule>').replace('</On module>', '</OnModule>') \
            .replace('<'+reflector+'  heard users>', '<HeardUsers><Reflector>'+reflector+'</Reflector>').replace('</'+reflector+'  heard users>', '</HeardUsers>') \
            .replace('<'+reflector+'  linked peers>', '<LinkedPeers><Reflector>'+reflector+'</Reflector>').replace('</'+reflector+'  linked peers>', '</LinkedPeers>') \
            .replace('<'+reflector+'  linked nodes>', '<LinkedNodes><Reflector>'+reflector+'</Reflector>').replace('</'+reflector+'  linked nodes>', '</LinkedNodes>')

        if (line.find("</") == -1) or line.startswith("</"):
            xmlfixed += line
            if line.lower().startswith("<?xml"):
                xmlfixed = xmlfixed + "<xlxd>"
        else:
            dict_data = xmltodict.parse(line)
            xmlfixed += ("<"+list(dict_data.keys())[0] + ">" + list(dict_data.values())[0] + "</" + list(dict_data.keys())[0] + ">")
      except:
        xmlfixed += line
        pass

    xmlfixed += "</xlxd>"

    MESSAGEJ = json.loads(json.dumps(xmltodict.parse(xmlfixed)))

    with open(LOG_PATH + "xlxd.json", 'w+') as outfile:
      json.dump(MESSAGEJ, outfile, indent=2)

    return MESSAGEJ

######################################################################
#
# COMMUNICATION WITH THE XLXD INSTANCE
#
def process_message(data):
    global reflector, modules, nodes, stations 
    
    if data.get("reflector") != None:
        reflector = data.get("reflector").strip()
        # print("reflector %r\r\n" % reflector)

    if data.get("modules") != None:
        modules = data.get("modules")
        # print("Modules \r\n")
    
    if data.get("nodes") != None:
        nodes = data.get("nodes")
        # print("Nodes %s\r\n" % str(nodes))

    if data.get("stations") != None:
        # {"callsign":"F5SZR","node":"F5ZTK","module":"B","time":"Tuesday Tue Aug 30 14:49:29 2022"}
        stations = data.get("stations")        
        # print("Stations %s\r\n" % str(stations))

    jsonStr = {
        "xlxd": {
            "Version": "2.4.0",
            "LinkedPeers": {
                "Reflector": reflector,
                "Peer": []
            },
            "LinkedNodes": {
                "Reflector": reflector,
                "Nodes": []
            },
            "HeardUsers": {
                "Reflector": reflector,
                "Station": []
            },
            "onair": data.get("onair"),
            "offair": data.get("offair")
        }
    }

    for item in nodes:
        callsign = item["callsign"].strip()

        entry = { 
            "Callsign": callsign + "   " + item["module"],
            "IP": "*.*.*.*",
            "LinkedModule": item["linkedto"].strip(),
            "Protocol": " ",
            "ConnectTime": item["time"].strip(),
            "LastHeardTime": item["time"].strip()
        }

        if item["module"] == " ":
            entry["Protocol"] = callsign[0:3]
            for peer in jsonStr["xlxd"]["LinkedPeers"]["Peer"]:
                if callsign == peer["Callsign"]:
                    peer["LinkedModule"] = peer["LinkedModule"] + entry["LinkedModule"]
                    break
            else:
                jsonStr["xlxd"]["LinkedPeers"]["Peer"].append(entry)
        else:
            jsonStr["xlxd"]["LinkedNodes"]["Nodes"].append(entry)

    for item in stations:
        callsign = item["callsign"].strip()
        OnModule = " "

        for node in nodes:
            if item["node"] == node["callsign"] and item["module"] == node["module"]:
                OnModule = node["linkedto"]
                break

        entry = { 
            "Callsign": callsign,
            "ViaNode": item["node"].strip() + " " + item["module"].strip(),
            "OnModule": OnModule,
            "ViaPeer": "",
            "LastHeardTime": item["time"].strip()
        }

        jsonStr["xlxd"]["HeardUsers"]["Station"].append(entry)

    for client in dashboard_server.clients:
        if client.page == "dashboard":
            client.sendMessage(json.dumps({ "TRAFFIC": jsonStr["xlxd"] , 'BIGEARS': str(len(dashboard_server.clients)), 'LISTENERS': LISTENERSJ }, ensure_ascii = False).encode('utf-8'))

def udpWorker(client, socket, buffSize):
    global __signals
    __SENDING_TIME_OUT = 0.25

    client.refresh()

    while not __signals["shutdown"]:
        data = socket.recvfrom(buffSize)
        if len(data):
            process_message(json.loads(data[0].replace(b"\x01", b"SOH")))
        ptime.sleep(__SENDING_TIME_OUT)

class UDP_Client:
    __connection_port=0
    __connection_address=0
    __buff_size=0
    
    def __init__(self, connection_address, connection_port):
        self.__connection_address = connection_address
        self.__connection_port = connection_port
        self.__buff_size = 32768
        print("Trying to connect to %s:%d\n" % (self.__connection_address, self.__connection_port))
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def sendMessage(self, message):
        self.__socket.sendto(message.encode("utf-8"), (self.__connection_address, self.__connection_port))

    def refresh(self):
        # print('sent %s message' %  "hello")
        self.sendMessage("hello")

    def run(self):
        try: 
            threading.Thread(target=udpWorker, args=(self, self.__socket, self.__buff_size)).start()
        except:
            pass

def timeout_clients():
    now = time()
    try:
        for client in dashboard_server.clients:
            if dashboard_server.clients[client] + CLIENT_TIMEOUT < now:
                logger.info('TIMEOUT: disconnecting client %s', dashboard_server.clients[client])
                try:
                    dashboard.sendClose(client)
                except Exception as e:
                    logger.error('Exception caught parsing client timeout %s', e)
    except:
        logger.info('CLIENT TIMEOUT: List does not exist, skipping. If this message persists, contact the developer')

# For importing HTML templates
def get_template(_file):
    with open(_file, 'r') as html:
        return html.read()

def creation_date(path_to_file):
    """
    Try to get the date that a file was created, falling back to when it was
    last modified if that isn't possible.
    See http://stackoverflow.com/a/39501288/1709587 for explanation.
    """
    if platform.system() == 'Windows':
        return os.path.getctime(path_to_file)
    else:
        stat = os.stat(path_to_file)
        try:
            return stat.st_birthtime
        except AttributeError:
            # We're probably on Linux. No easy way to get creation dates here,
            # so we'll settle for when its content was last modified.
            return stat.st_mtime

def retrieveReflectorList():
    logging.info('requesting: reflectorlist.xml')

    filename = "reflectorlist.xml"
    filepath = LOG_PATH + filename

    # keep shield file always updated
    if os.path.exists(filepath):
        _time = int(time()) - int(creation_date(filepath))
        # check if file needs new download from remote
        if int(_time/60/60/24) < 7:
            with open(filepath, 'r') as infile:
                return infile.read()

    fileurl = "http://xlxapi.rlx.lu/api.php?do=GetReflectorList"

    # file is older than 7 days, download 
    with urllib.request.urlopen(fileurl) as url:
        with open(filepath, 'wb+') as outfile:
            xml = url.read().decode("utf-8")

            xml = '<?xml version="1.0" encoding="UTF-8" standalone="no" ?>\r\n' + xml.replace("&amp;", "&#38;").replace("&lt;", "&#60;").replace("&gt;", "&#62;") \
                        .replace("&Uuml;", "Ü").replace("&quot;", "&#39;").replace("&ograve;", "ò") \
                        .replace("&uuml;", "ü").replace("&ndash;", "–").replace("&uacute;", "ú").replace("&ldquo;", "\"").replace("&rdquo;", "\"")

            outfile.write(xml.encode("utf-8"))
            outfile.close()
            return xml

    return None

def getReflectorList():
    xml = retrieveReflectorList()
    if xml != None:
        dict = xmltodict.parse(xml)
        reflectorList = dict["XLXAPI"]["answer"]["reflectorlist"]

        jsonStr = []

        for item in reflectorList["reflector"]:
            uptime = int(item.get("uptime")) / (3600*24)

            if int(item.get("lastcontact")) / (3600*24*1000) > uptime:
                uptime = "down"
            else:
                uptime = str(int(uptime)) + " days"

            jsonStr.append({ 
                "name": item.get("name"),
                "lastip": item.get("lastip"),
                "dashboardurl": item.get("dashboardurl"),
                "uptime": uptime,
                "lastcontact":  item.get("lastcontact"),
                "country": item.get("country"),
                "comment":  item.get("comment")
            })

        return jsonStr

        # print("reflector : %s, country : %s, uptime : %s, comment : %s" % (item.get("name"), item.get("country"), uptime, item.get("comment")))

    return {}

def replaceSystemStrings(data):
    return data.replace("<<<site_logo>>>", sitelogo_html).replace("<<<system_name>>>", REPORT_NAME) \
        .replace("<<<button_bar>>>", BUTTONBAR_HTML) \
        .replace("<<<MOD_FILTER>>>", str(MOD_FILTER)) \
        .replace("<<<MOD_ORDER>>>", str(MOD_ORDER)) \
        .replace("<<<MOD_HILITE>>>", str(MOD_HILITE)) \
        .replace("<<<MOD_COLORS>>>", str(MOD_COLORS)) \
        .replace("<<<MOD_NUMBER>>>", str(MOD_NUMBER)) \
        .replace("<<<MOD_NAMES>>>", str(MOD_NAMES)) \
        .replace("<<<SOCKET_SERVER_PORT>>>", str(SOCKET_SERVER_PORT)) \
        .replace("<<<DISPLAY_LINES>>>", str(DISPLAY_LINES)) \
        .replace("<<<LAST_ACTIVE_MOD>>>", str(LAST_ACTIVE_MOD)) \
        .replace("<<<LAST_ACTIVE_SIZE>>>", str(LAST_ACTIVE_SIZE)) \
        .replace("<<<DYNAMIC_MOD>>>", str(DYNAMIC_MOD))

private_secret = os.urandom(64)

def generateRandomSessionKey():
    session_key = binascii.hexlify(os.urandom(16))
    return session_key

def load_dictionary(_message):
    data = _message[1:]
    logging.debug('Successfully decoded dictionary')
    return loads(data)

######################################################################
#
# WEBSOCKET COMMUNICATION WITH THE DASHBOARD CLIENT
#
class dashboard(WebSocketServerProtocol):
    def onConnect(self, request):
        logging.info('Client connecting: %s', request.peer)
        if 'page' in request.params:
            self.page = request.params["page"][0]
            logging.info('Client Page: %s', self.page)
        else:
            self.page = ""

    def onOpen(self):
        logging.info('WebSocket connection open.')
        self.factory.register(self)

        if self.page == "reflectors":
            self.sendMessage(json.dumps({"REFLECTORS": getReflectorList() }, ensure_ascii = False).encode('utf-8'))
        else:
            _message = {}

            _message["PACKETS"] = {}
            _message["BIGEARS"] = str(len(dashboard_server.clients))
            _message["LISTENERS"] = LISTENERSJ

            INITIALLIST = {}

            # read saved history or create traffic file for later
            #if not os.path.exists(LOG_PATH + "xlxd.json"):
            createLogTableJson()

            with open(LOG_PATH + "xlxd.json", 'r') as infile:
                _traffic = json.load(infile)

                if _traffic and _traffic["xlxd"]:
                    INITIALLIST = _traffic["xlxd"]
                else:
                    logging.info("Creating empty " + LOG_PATH + "xlxd.json")
                    with open(LOG_PATH + "xlxd.json", 'w') as outfile:
                        json.dump({ "TRAFFIC" : [] }, outfile)
                        
                infile.close()

            # sorted in reverse order last in log becomes first to display
            # https://linuxhint.com/sort-json-objects-python/
            _message["PACKETS"] = { "TRAFFIC": INITIALLIST }

            self.sendMessage(json.dumps({ "CONFIG": _message }, ensure_ascii = False).encode('utf-8'))

            logger.info('Deleting INITIALLIST after init')
            del _message
            del INITIALLIST

    def onMessage(self, payload, isBinary):
        try: 
            if not isBinary:
                _command = json.loads(payload.decode('utf-8'))
                logging.info("command received: {}".format(_command))
                if _command and _command.get("request") == "reflectors":
                    self.sendMessage(json.dumps({"REFLECTORS": getReflectorList() }, ensure_ascii = False).encode('utf-8'), isBinary)
            
        except CalledProcessError as err:
            logging.info('Error: %s', err)


    def connectionLost(self, reason):
        WebSocketServerProtocol.connectionLost(self, reason)
        self.factory.unregister(self)
        
    def onClose(self, wasClean, code, reason):
        logging.info('WebSocket connection closed: %s', reason)

class dashboardFactory(WebSocketServerFactory):
    def __init__(self, url):
        WebSocketServerFactory.__init__(self, url)
        self.clients = {}

        # start XLXD json thread to get updates from server
        xlx_client = UDP_Client(XLXD_IP, XLXD_PORTJSON)
        xlx_client.run()

    def register(self, client):
        if client not in self.clients:
            logging.info('registered client %s', client.peer)
            self.clients[client] = time()

    def unregister(self, client):
        if client in self.clients:
            logging.info('unregistered client %s', client.peer)
            del self.clients[client]

    def broadcast(self, msg):
        logging.debug('broadcasting message to: %s', self.clients)
        for c in self.clients:
            c.sendMessage(json.dumps(msg, ensure_ascii = False).encode('UTF-8'))
            logging.debug('message sent to %s', c.peer)

######################################################################
#
# STATIC WEBSERVER
#
class staticHtmlFile(Resource):
    def __init__(self, file_Name, file_Folder, file_contentType):
        self.file_Name = file_Name
        self.file_Folder = file_Folder
        self.file_contentType = file_contentType
        Resource.__init__(self)

    def render_GET(self, request):
        filepath = "{}/{}".format(PATH + self.file_Folder, self.file_Name.decode("UTF-8"))

        if os.path.exists(filepath):
            request.setHeader('content-disposition', 'filename=' + self.file_Name.decode("UTF-8"))
            request.setHeader('content-type', self.file_contentType)
            return replaceSystemStrings(get_template(filepath)).encode("utf-8")

        request.setResponseCode(http.NOT_FOUND)
        request.finish()
        return NoResource()

class staticFile(Resource):
    def __init__(self, file_Name, file_Folder, file_contentType):
        self.file_Name = file_Name
        self.file_Folder = file_Folder
        self.file_contentType = file_contentType
        Resource.__init__(self)

    def render_GET(self, request):
        @defer.inlineCallbacks
        def _feedfile():
            if self.file_Folder != "/tmp":
                filepath = "{}/{}".format(PATH + self.file_Folder, self.file_Name.decode("UTF-8"))
            else:
                filepath = "{}/{}".format(self.file_Folder, self.file_Name.decode("UTF-8"))

            self.file_size = os.path.getsize(filepath)

            logging.info(filepath)

            @defer.inlineCallbacks
            def _setContentDispositionAndSend(file_path, file_name, content_type):
                request.setHeader('content-disposition', 'filename=' + file_name.decode("UTF-8"))
                request.setHeader('content-length', str(self.file_size))
                request.setHeader('content-type', content_type)

                with open(file_path, 'rb') as f:
                    yield FileSender().beginFileTransfer(f, request)
                    f.close()

                defer.returnValue(0)

            if os.path.exists(filepath):
                yield _setContentDispositionAndSend(filepath, self.file_Name, self.file_contentType)
            else:
                request.setResponseCode(http.NOT_FOUND)
            
            request.finish()

            defer.returnValue(0)

        _feedfile()
        return server.NOT_DONE_YET

class IAuthenticated(Interface):
    mode = Attribute("A value 0 or 1 meaning User or Admin")
    value = Attribute("A boolean indicating session has been authenticated")

@implementer(IAuthenticated)
class Authenticated(object):
    def __init__(self, session):
        self.value = False
        self.mode = 0

registerAdapter(Authenticated, Session, IAuthenticated)

def index_template():
    return replaceSystemStrings(get_template(PATH + "templates/index_template.html")).encode('utf-8')

class reflectors(Resource):
    def __init__(self):
        Resource.__init__(self)

    def render_GET(self, request):
        return str.encode(replaceSystemStrings(get_template(PATH + "templates/reflectors.html")))
        
class web_server(Resource):
    def __init__(self):
        Resource.__init__(self)

    def getChild(self, name, request):
        session = request.getSession()
        authenticated = IAuthenticated(session)
        if authenticated.value != True:
            return self

        page = name.decode("utf-8")

        if page == '' or page == 'index.html':
            return self

        if page == 'reflectors.html':
            return reflectors()

        # deal with static files (images, css etc...)
        # call static file with file name, location folder, controlType
        #
        if page.endswith(".html") or page.endswith(".htm"):
            return staticHtmlFile(name, "html", "text/html; charset=utf-8")
        if page.endswith(".css"):
            return staticFile(name, "css", "text/css; charset=utf-8")
        elif page.endswith(".js"):
            return staticFile(name, "scripts", "application/javascript; charset=utf-8")
        elif page.endswith(".jpg") or page.endswith(".jpeg"):
            return staticFile(name, "images", "image/jpeg")
        elif page.endswith(".gif"):
            return staticFile(name, "images", "image/gif")
        elif page.endswith(".png"):
            return staticFile(name, "images", "image/png")
        elif page.endswith(".svg"):
            return staticFile(name, "images", "image/svg+xml")
        elif page.endswith(".ico"):
            return staticFile(name, "images", "image/x-icon")
        elif page.endswith(".json") or page.endswith(".webmanifest"):
            return staticFile(name, "assets", "application/json")
        elif page.endswith(".txt"):
            return staticFile(name, "html", "text/plain")
        elif page.endswith(".woff2"):
            return staticFile(name, "webfonts", "font/woff2;")
        elif page.endswith(".woff"):
            return staticFile(name, "webfonts", "font/woff;")
        elif page.endswith(".ttf"):
            return staticFile(name, "webfonts", "font/ttf;")

        return NoResource()

    def render_GET(self, request):
        admin_auth = False
        logging.info('static website requested: %s', request)
        session = request.getSession()
        authenticated = IAuthenticated(session)

        url = URL.fromText(request.uri.decode('ascii'))
        if len(url.get("admin")) > 0:
            admin_auth = True

        if WEB_AUTH or admin_auth:
            admin_login = ADMIN_USER.encode('utf-8')
            admin_password = ADMIN_PASS.encode('utf-8')

            user = WEB_USER.encode('utf-8')
            password = WEB_PASS.encode('utf-8')

            auth = request.getHeader('Authorization')
            if auth and auth.split(' ')[0] == 'Basic':
                decodeddata = base64.b64decode(auth.split(' ')[1])
                if (decodeddata.split(b':') == [user, password] and not admin_auth) or (decodeddata.split(b':') == [admin_login, admin_password] and admin_auth):
                    global BUTTONBAR_HTML

                    logging.info('Authorization OK')
                    authenticated.value = True
                    if decodeddata.split(b':') == [user, password]:
                        authenticated.mode = 0
                        # update button bar template
                        logging.info('user logging, switching to user menu')
                        BUTTONBAR_HTML = get_template(PATH + "templates/buttonbar.html")
                    else:
                        authenticated.mode = 1
                        # update button bar template
                        logging.info('admin logging, switching to admin menu')
                        BUTTONBAR_HTML = get_template(PATH + "templates/admin_buttonbar.html")

                    return index_template()

            authenticated.value = False
            authenticated.mode = 0
            request.setResponseCode(http.UNAUTHORIZED)
            request.setHeader('www-authenticate', 'Basic realm="realmname"')
            logging.info('Someone wanted to get access without authorization')

            return "<html<head></hread><body style=\"background-color: #EEEEEE;\"><br><br><br><center> \
                    <fieldset style=\"width:600px;background-color:#e0e0e0e0;text-algin: center; margin-left:15px;margin-right:15px; \
                     font-size:14px;border-top-left-radius: 10px; border-top-right-radius: 10px; \
                     border-bottom-left-radius: 10px; border-bottom-right-radius: 10px;\"> \
                  <p><font size=5><b>Authorization Required</font></p></filed></center></body></html>".encode('utf-8')
        else:
            authenticated.value = True
            authenticated.mode = 0
            return index_template()

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        filename = (LOG_PATH + LOG_NAME),
        filemode='a',
        format='%(asctime)s %(levelname)s %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    console = logging.StreamHandler()
    console.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    logger = logging.getLogger(__name__)

    logging.info('xlxdmonitor.py starting up')

    logger.info('\n\n\tXLXJSON v1.1.0:\n\tCopyright (c) 2022 Jean-Michel Cohen, F4JDN <f4jdn@outlook.fr>\n\n')

    # Create Static Website index file
    sitelogo_html = get_template(PATH + "templates/sitelogo.html")
    BUTTONBAR_HTML = get_template(PATH + "templates/buttonbar.html")

    # Start a timeout loop
    if CLIENT_TIMEOUT > 0:
        timeout = task.LoopingCall(timeout_clients)
        timeout.start(10)

    # Create websocket server to push content to clients
    dashboard_server = dashboardFactory('ws://*:{}'.format(SOCKET_SERVER_PORT))
    dashboard_server.protocol = dashboard

    # Function to accept offers from the client ..
    def accept(offers):
        for offer in offers:
            if isinstance(offer, PerMessageDeflateOffer):
                return PerMessageDeflateOfferAccept(offer)

    dashboard_server.setProtocolOptions(perMessageCompressionAccept=accept)

    reactor.listenTCP(SOCKET_SERVER_PORT, dashboard_server)

    # Create static web server to push initial index.html
    root = web_server()
    factory = Site(root)
    endpoint = endpoints.TCP4ServerEndpoint(reactor, JSON_SERVER_PORT)
    endpoint.listen(factory)

    reactor.run()
