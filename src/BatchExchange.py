#! /usr/bin/env python3

_HELP = """
# Examples

%(prog)s repl
>>> trex.info()
>>> trex.set_credentials("admin","admin")
>>> trex.set_batchsystem("slurm")
>>> trex.set_xcat_connection(host="192.168.56.10", port=443, ssl=True, ssl_verify=False)
>>> trex.set_xcat_credentials(username="root", password="root")
>>> trex.xcat_get_nodes()

%(prog)s --xcat-host=192.168.56.10 --xcat-user=root --xcat-password=root --password=admin --batchsystem slurm deploy --nodes node1 --osimage sles12.3-ppc64-install-compute
"""

__all__ = ["API", "Resp", "AttrDict", "APIBase", "main"]

import base64
import argparse
import urllib.parse
import urllib.request
import urllib.error
import json
import sys
import ssl
import collections
import logging
import getpass
import contextlib
import time

#: A special loglevel that is used for command line output of cw_webgateway_cli
_NOTICE = 25

# default loglevel to use
_LOG_LEVEL = "NOTICE"

logger = logging.getLogger("cw_webgateway_cli")
logger.addHandler(logging.NullHandler())


# log messages to use (more verbose for debug level)
_LOGMESSAGE_DEBUG = '[%(asctime)s] %(levelname)s: %(module)s:%(lineno)d >> %(message)s'
_LOGMESSAGE_NORMAL = '%(message)s'

#region helper module

Resp = collections.namedtuple("Resp", ['data', 'raw', 'response'])

def set_session(session, args, ask=True):
    if ask and args.password is None:
        args.password =  getpass.getpass("Password> ") # hide input for password prompt
    session.set_credentials(args.username, args.password)
    session.set_batchsystem(args.batchsystem)

def set_xcat_session(session, args, ask=True):
    if ask and args.xcat_password is None:
        args.xcat_password =  getpass.getpass("XCAT Password> ") # hide input for password prompt
    session.set_xcat_connection(host=args.xcat_host, port=args.xcat_port, ssl=(not args.xcat_no_ssl), ssl_verify=args.xcat_verify_ssl)
    session.set_xcat_credentials(username=args.xcat_user, password=args.xcat_password)

def _repl(vars):
    import code

    try:
        import readline
        import rlcompleter
        readline.set_completer(rlcompleter.Completer(vars).complete)
        readline.parse_and_bind("tab: complete")
    except:
        pass
    code.InteractiveConsole(vars).interact()

class AttrDict(dict):
    def __init__(self, *args, **kwargs):
        super(AttrDict, self).__init__(*args, **kwargs)
        self.__dict__ = self

class APIError(Exception):
    def __init__(self, message, data, raw):
        super().__init__(message)
        self.data = data
        self.raw = raw

def _load_json(raw):
    try:
        return json.loads(raw)
    except json.decoder.JSONDecodeError:
        return None



class APIBase:
    def __init__(self, base_uri, api_uri="", verify_ssl=True, auto_revoke=False, ignore_error=False):
        self.verify_ssl = verify_ssl
        self.logged_in = None
        self.auto_revoke = auto_revoke
        self.base_uri = base_uri
        self.api_uri = api_uri
        self.ignore_error = ignore_error
        self.username = None
        self.password = None

    @contextlib.contextmanager
    def errors_ignored(self):
        try:
            self.ignore_error = True
            yield self
        finally:
            self.ignore_error = False

    def set_credentials(self, username, password):
        self.username = username
        self.password = password

    def request(self, uri, data = None, method=None, form = False, headers = None, auth = None, verify_ssl = None, ignore_error = None, base_uri = None, api_uri = None, wrap=False, wrap_attr = False, **request_opts):
        verify_ssl = self.verify_ssl if verify_ssl is None else verify_ssl
        base_uri = self.base_uri if base_uri is None else base_uri
        api_uri = self.api_uri if api_uri is None else api_uri
        ignore_error = self.ignore_error if ignore_error is None else ignore_error

        if api_uri is False:
            api_uri = ""

        if headers is None:
            headers = {}

        if auth is not False and self.username and "Authorization" not in headers:
            headers["Authorization"] = 'Basic '+base64.b64encode((self.username+":"+self.password).encode("utf-8")).decode("ascii")

        if data is not None:
            if form:
                data = urllib.parse.urlencode(data).encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                headers["Content-Type"] = "application/json"
                data = json.dumps(data).encode("utf-8")

        req = urllib.request.Request(base_uri+api_uri+uri, data=data, headers=headers, method=method)

        if not verify_ssl:
            request_opts["context"]=ssl._create_unverified_context()

        try:
            with urllib.request.urlopen(req, **request_opts) as response:
                raw = response.read()
                json_data = _load_json(raw)
                data = AttrDict(json_data) if wrap_attr else json_data
                return Resp(data=data, raw=raw, response=response) if wrap else data
        except urllib.error.URLError as e:
            try:
                raw = e.read()
                json_data = _load_json(raw)
            except AttributeError:
                raw = None
                json_data = None

            if ignore_error:
                return Resp(data=json_data, raw=raw, response=e)
            else:
                raise APIError(str(e), json_data, raw) from e

    def get(self, *args, **kwargs):
        return self.request(*args, method="GET", **kwargs)
    def post(self, *args, **kwargs):
        return self.request(*args, method="POST", **kwargs)
    def patch(self, *args, **kwargs):
        return self.request(*args, method="PATCH", **kwargs)
    def put(self, *args, **kwargs):
        return self.request(*args, method="PUT", **kwargs)
    def delete(self, *args, **kwargs):
        return self.request(*args, method="DELETE", **kwargs)
    def options(self, *args, **kwargs):
        return self.request(*args, method="OPTIONS", **kwargs)
        

class API(APIBase):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.batchsystem = None
        self.xcat_password = None
        self.xcat_username = None
        self.xcat_token = None
        self.xcat_host = None
        self.xcat_port = 443
        self.xcat_ssl = True
        self.xcat_ssl_verify = False

    def set_batchsystem(self, batchsystem):
        self.batchsystem = batchsystem

    def set_xcat_connection(self, host, port=443, ssl=True, ssl_verify=False):
        self.xcat_host = host
        self.xcat_port = port
        self.xcat_ssl = ssl
        self.xcat_ssl_verify = ssl_verify

    def set_xcat_token(self, token):
        self.xcat_token = token

    def set_xcat_credentials(self, username, password):
        self.xcat_username = username
        self.xcat_password = password

    def _get_xcat_options(self):
        opts = [("host="+self.xcat_host), ("port="+str(self.xcat_port)), ("ssl="+("true" if self.xcat_ssl else "false")), ("ssl_verify="+("true" if self.xcat_ssl_verify else "false"))]
        if self.xcat_token is not None:
            opts.append("token="+self.xcat_token)
        elif self.xcat_username is not None and self.xcat_password is not None:
            opts.append("user="+self.xcat_username)
            opts.append("password="+self.xcat_password)
        return "&".join(opts)

    def info(self):
        return self.get("/info")
    
    def _check_batchsystem(self):
        if not self.batchsystem: raise ValueError("Batchsystem not set")

    def get_nodes(self):
        self._check_batchsystem()
        return self.get("/nodes?batchsystem="+self.batchsystem)

    def check_drained(self, nodes):
        get_nodes_obj = self.get_nodes()
        print(get_nodes_obj)
        nodes_to_drain = {}
        for n in nodes:
            nodes_to_drain[n] = "UNKNOWN"
        set(nodes)
        for o in get_nodes_obj["data"]:
            if o["name"] in nodes_to_drain:
                nodes_to_drain[o["name"]] = o["rawState"]
                states = o["rawState"].lower().split("+")
                if "drained" in states or "down" in states:
                    nodes_to_drain.pop(o["name"])
        return nodes_to_drain

    def set_node_state(self, node, state, reason):
        self._check_batchsystem()
        return self.post("/nodes/"+node+"/state?batchsystem="+self.batchsystem, data={"state": state, "reason": reason})

    def xcat_get_nodes(self):
        return self.get("/xcat/nodes?"+self._get_xcat_options())

    def xcat_get_osimages(self):
        return self.get("/xcat/osimages?"+self._get_xcat_options())

    def xcat_get_groups(self):
        return self.get("/xcat/groups?"+self._get_xcat_options())

    def xcat_set_group_attributes(self, filter, provmethod=None, prescripts=None, postbootscripts=None, postscripts=None, **attrs):
        o = {**attrs}
        if provmethod is not None: o["provmethod"] = provmethod
        if prescripts is not None: o["prescripts"] = prescripts
        if postbootscripts is not None: o["postbootscripts"] = postbootscripts
        if postscripts is not None: o["postscripts"] = postscripts
        return self.put("/xcat/groupattrs?"+self._get_xcat_options(), data={"filter": filter, "attributes": o})

    def xcat_set_bootstate(self, filter, osimage):
        return self.put("/xcat/bootstate?"+self._get_xcat_options(), data={"filter": filter, "osimage": osimage})

    def xcat_set_nextboot(self, filter, order):
        return self.put("/xcat/nextboot?"+self._get_xcat_options(), data={"filter": filter, "order": order})

    def xcat_set_powerstate(self, filter, action):
        return self.put("/xcat/bootstate?"+self._get_xcat_options(), data={"filter": filter, "action": action})


    def deploy(self, osimage, nodes=None, groups=None, reason="redeployment", provmethod=None, prescripts=None, postbootscripts=None, postscripts=None, drain_interval=5):

        if nodes is None and groups is None:
            raise ValueError("Either select nodes or groups")

        available_images = [*self.xcat_get_osimages()["data"].keys()]
        if osimage not in available_images:
            raise ValueError("osimage not found in available images: "+", ".join(available_images))

        if groups is not None:
            groupdata = self.xcat_get_groups()["data"]
            nodes = []
            for g in groups:
                for n in groupdata[g]["members"]:
                    nodes.append(n)
            
            print("Found nodes for groups: "+", ".join(nodes))
        
        print("Set nodes to draining")
        for node in nodes:
            ret = self.set_node_state(node, "drain", reason=reason)
            print(ret)
            if not ret["data"]["success"]:
                raise ValueError("Error draining "+node)

        while True:
            rest = self.check_drained(nodes)
            if len(rest) == 0:
                break
            else:
                print("Waiting for nodes to drain: "+", ".join(k+"("+v+")" for k, v in rest.items()))
            time.sleep(drain_interval)

        print("Set group attributes")
        self.xcat_set_group_attributes(nodes if groups is None else groups, provmethod=provmethod, prescripts=prescripts, postbootscripts=postbootscripts, postscripts=postscripts)

        print("Set osimage")
        self.xcat_set_bootstate(nodes, osimage)

        print("Set netboot for next start to ensure provisioning")
        self.xcat_set_nextboot(nodes, "net")

        print("Request restart of nodes")
        self.xcat_set_powerstate(nodes, "reset")


#endregion


#region cli

def format_nested(d, path, outlist):
    if isinstance(d, dict):
        prefix = path+"." if path else ""
        for k, v in d.items():
            format_nested(v, prefix+k, outlist)
    elif isinstance(d, list):
        for i, v in enumerate(d):
            format_nested(v, path+"["+str(i)+"]", outlist)
    else:
        outlist.append(path+": "+str(d))

def format_dict(d, output):
    if output == "json":
        return json.dumps(d, separators=(',', ':'))
    elif output == "json_pretty":
        return json.dumps(d, indent=4)
    elif output == "print":
        out = []
        format_nested(d, "", out)
        return "\n".join(out)

    return str(d)

def _info(session, args):
    logger.log(_NOTICE, format_dict(session.info(), args.output))

def _repl_wrapper(vars):
    import code

    try:
        import readline
        import rlcompleter
        readline.set_completer(rlcompleter.Completer(vars).complete)
        readline.parse_and_bind("tab: complete")
    except:
        pass
    code.InteractiveConsole(vars).interact()


def _repl(session, args):
    print("Session initialized as `trex`. Type `help(trex)` for assistance")
    globvars = globals()
    vars = {v: globvars[v] for v in __all__}
    vars.update({"trex": session})
    set_session(session, args, False)
    set_xcat_session(session, args, False)
    session.ignore_error = True
    _repl_wrapper(vars)
    sys.exit(0)

def _nodes(session, args):
    set_session(session, args)
    logger.log(_NOTICE, format_dict(session.get_nodes(), args.output))

def _xcatnodes(session, args):
    set_session(session, args)
    set_xcat_session(session, args)
    logger.log(_NOTICE, format_dict(session.xcat_get_nodes(), args.output))


def _deploy(session, args):
    set_session(session, args)
    set_xcat_session(session, args)
    #session.ignore_error = False
    try:
        session.deploy(osimage=args.osimage, nodes=args.nodes, groups=args.groups, reason=args.reason, provmethod=args.provmethod, postbootscripts=args.postbootscripts, postscripts=args.postscripts)
    except ValueError as msg:
        print(msg)

def _show_osimages(session, args):
    set_session(session, args)
    set_xcat_session(session, args)
    logger.log(_NOTICE, "\n".join(session.xcat_get_osimages()["data"].keys()))

_cmds = {
    "info": _info,
    "repl": _repl,
    "nodes": _nodes,
    "deploy": _deploy,
    "osimages": _show_osimages,
    "xcatnodes": _xcatnodes,
}

def _create_parser():
    parser = argparse.ArgumentParser(description='Control webgateway authorization.', epilog=_HELP, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--uri', type=str, help='Base URI to webgateway', default="https://127.0.0.1:2000")
    parser.add_argument('-u', '--username', type=str, help='Username', default="admin")
    parser.add_argument('-p', '--password', type=str, help='Password')
    parser.add_argument('--output', choices=['print', 'parse', 'json', 'json_pretty'], default="print", help="Print responses as single parse value or json instead of column text")
    parser.add_argument('--verify-ssl', action='store_true', help="Enable ssl certificate validation")
    parser.add_argument('-l', '--loglevel', type=str, choices=["DEBUG", "INFO", "NOTICE", "WARNING", "ERROR", "CRITICAL"], default="NOTICE", help='Set log level (default: {})'.format(_LOG_LEVEL))


    parser.add_argument('--xcat-host', type=str, help='Xcat host')
    parser.add_argument('--xcat-token', type=str, help='Xcat token')
    parser.add_argument('--xcat-port', type=int, help='Xcat port', default=443)
    parser.add_argument('--xcat-user', type=str, help='Xcat user', default="root")
    parser.add_argument('--xcat-password', type=str, help='Xcat password')
    parser.add_argument('--xcat-verify-ssl', action='store_true', help="Enable xcat ssl certificate validation")
    parser.add_argument('--xcat-no-ssl', action='store_true', help="Do not use ssl for xcat connection")

    subparsers = parser.add_subparsers(help="Available subcommands", dest="cmd") # required=True only supported from py3.7+
    parser_repl = subparsers.add_parser('repl', help='Open python repl')

    parser_info = subparsers.add_parser("info", help="Get trex info")

    parser.add_argument('--batchsystem', type=str, help="Batchsystem")
    parser_nodes = subparsers.add_parser("nodes", help="Get batchsystem nodes")

    parser_deploy = subparsers.add_parser("deploy", help="Reprovision and deploy nodes")
    parser_deploy.add_argument('--osimage', type=str, help='Osimage to provision', required=True)
    parser_deploy.add_argument('--reason', type=str, help='Reason for batchsystem drain operation', default="redeployment")

    group = parser_deploy.add_mutually_exclusive_group(required=True)
    group.add_argument('--nodes', type=str, nargs='+', help='Nodes to provision')
    group.add_argument('--groups', type=str, nargs='+', help='Groups to provision')

    parser_deploy.add_argument('--provmethod', type=str, help='provmethod')
    parser_deploy.add_argument('--prescripts', type=str, help='prescripts')
    parser_deploy.add_argument('--postbootscripts', type=str, help='postbootscripts')
    parser_deploy.add_argument('--postscripts', type=str, help='postscripts')

    parser_osimages = subparsers.add_parser("osimages", help="Show osimages")
    parser_xcatnodes = subparsers.add_parser("xcatnodes", help="Get xcat nodes")

    return parser



def main():

    parser = _create_parser()
    args = parser.parse_args()

    logging.addLevelName(_NOTICE, "NOTICE")
    logger.addHandler(logging.StreamHandler())
    logger.setLevel(args.loglevel)
    logger.handlers[1].setFormatter(logging.Formatter(_LOGMESSAGE_DEBUG if args.loglevel == "DEBUG" else _LOGMESSAGE_NORMAL))

    if args.cmd in _cmds:
        session = API(verify_ssl=args.verify_ssl, base_uri=args.uri)
        session.ignore_error = True
        _cmds[args.cmd](args=args, session=session)
    else: # needed without subparsers required=True
        parser.print_help(sys.stderr)
        sys.exit(1)

#endregion


if __name__ == "__main__":
    main()
