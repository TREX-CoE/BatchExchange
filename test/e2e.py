import subprocess
import ssl
import websocket # pip install websocket-client

URI = "127.0.0.1:2000"
CRED = "admin:admin"
VERBOSE = 1

def req(uri, json=None, method=None):
    cmd = ["curl", "--insecure", "-w", "\n%{http_code}\n", "-u", CRED, f'https://{URI}{uri}']
    if json is not None:
        cmd.extend(["-H", "Content-Type: application/json", "-d", json])
    if method is not None:
        cmd.extend(["-X", method])
    if VERBOSE >= 2:
        print("$ " + " ".join(repr(i) for i in cmd))
    elif VERBOSE >= 1:
        print(f"> {uri} {json}")
    return subprocess.run(cmd)

def test_rest():
    req("/nodes?batchsystem=pbs")
    req("/nodes?batchsystem=slurm")
    req("/users", '{"user": "e", "password": "a", "scopes": ["aa"]}')

def test_ws():
    ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
    ws.connect(f"wss://{URI}")

    def comm(json):
        if VERBOSE >= 1:
            print(f"> {json}")
        ws.send(json)
        resp = ws.recv()
        if VERBOSE >= 1:
            print(resp)
        return resp


    comm('{"command": "login", "user": "admin", "password": "admin"}')
    comm('{"command": "getNodes", "batchsystem": "pbs"}')
    comm('{"command": "logout"}')

test_ws()