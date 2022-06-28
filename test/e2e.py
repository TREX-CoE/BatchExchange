from math import radians
import subprocess
import ssl
import websocket # pip install websocket-client
import json
import unittest
import os

URI = os.getenv("TEST_URI", "127.0.0.1:2000")
VERBOSITY = int(os.getenv("TEST_VERBOSITY", "0"))
CRED = "admin:admin"

def req(uri, data=None, method=None, cred=CRED):
    cmd = ["curl", "--insecure", "-w", "\n%{http_code}", "-u", CRED, f'https://{URI}{uri}']
    if data is not None:
        cmd.extend(["-H", "Content-Type: application/json", "-d", json.dumps(data)])
    if method is not None:
        cmd.extend(["-X", method])
    if VERBOSITY >= 2:
        print("$ " + " ".join(repr(i) for i in cmd))
    elif VERBOSITY >= 1:
        print(f"> {uri} {json.dumps(data) if data is not None else ''}")
    out = subprocess.run(cmd, capture_output=True)
    parts = out.stdout.decode().split("\n")
    try:
        body = json.loads(parts[0])
    except:
        body = parts[0]
    
    try:
        status = int(parts[1])
    except:
        status = parts[1]
    
    if VERBOSITY >= 1:
        print(f"{json.dumps(body)} {status}")
    return body, status

def create_comm():
    ws = websocket.WebSocket(sslopt={"cert_reqs": ssl.CERT_NONE})
    ws.connect(f"wss://{URI}")

    def comm(j):
        s = json.dumps(j)
        if VERBOSITY >= 1:
            print(f"> {s}")
        ws.send(s)
        resp = ws.recv()
        if VERBOSITY >= 1:
            print(resp)
        return json.loads(resp)

    return comm

class TestRest(unittest.TestCase):
    def test_remove_add_unknown_user(self):
        self.assertEqual(req("/users/notthere", method="DELETE"), ({"error": {"type": "NotFound", "message": "user notthere not found", "code": 404}}, 404))
        self.assertEqual(req("/users", {"user": "notthere", "password": "notthere", "scopes": ["a"]}), ({'scopes': ["a"], 'username': 'notthere'}, 201))
        self.assertEqual(req("/users/notthere", method="DELETE"), ({'data': {'success': True}}, 200))

    def test_nodes_pbs(self):
        data, status = req("/nodes?batchsystem=pbs")
        self.assertEqual(status, 200)
        self.assertTrue("data" in data)
        self.assertTrue(len(data["data"]) > 0)
        self.assertTrue(len(data["data"][0].get("name", "")) > 0)

    def test_nodes_slurm(self):
        data, status = req("/nodes?batchsystem=slurm")
        self.assertEqual(status, 200)
        self.assertTrue("data" in data)
        self.assertTrue(len(data["data"]) > 0)
        self.assertTrue(len(data["data"][0].get("name", "")) > 0)

class TestWebsocket(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        comm = create_comm()
        cls.comm = lambda self, d: comm(d)

    def test_01_invalid_login(self):
        self.assertEqual(self.comm({"command": "login", "user": "notthere", "password": "admin"}), {"error":{"type":"Invalid login","message":"Could not authenticate user for login","code":401}})

    def test_02_valid_login(self):
        data = self.comm({"command": "login", "user": "admin", "password": "admin"})
        self.assertTrue("data" in data)
        self.assertTrue(len(data["data"].get("scopes", [])) > 0)

    def test_03_getNodes(self):
        data = self.comm({"command": "getNodes", "batchsystem": "pbs", "filterNodes": ["ubuntu"]})
        self.assertTrue("data" in data)
        self.assertTrue(len(data["data"]) > 0)
        self.assertTrue(len(data["data"][0].get("name", "")) > 0)
        
    def test_04_getJobs(self):
        data = self.comm({"command": "getJobs", "batchsystem": "pbs", "filterJobs": []})
        self.assertTrue("data" in data)
        self.assertTrue(len(data["data"]) > 0)
        self.assertTrue(len(data["data"][0].get("id", "")) > 0)

    def test_05_getQueues(self):
        data = self.comm({"command": "getQueues", "batchsystem": "pbs"})
        self.assertTrue("data" in data)
        self.assertTrue(len(data["data"]) > 0)
        self.assertTrue(len(data["data"][0].get("name", "")) > 0)

    def test_06_remove_unknown_user(self):
        self.assertEqual(self.comm({"command": "usersDelete", "user": "notthere"}), {"error": {"type": "NotFound", "message": "user notthere not found", "code": 404}})

    def test_07_detect(self):
        self.assertEqual(self.comm({"command": "detect", "batchsystem": "pbs"}), {'data': {'detected': True}})


    def test_08_logout(self):
        self.assertEqual(self.comm({"command": "logout"}), {"success": True})


if __name__ == '__main__':
    unittest.main()
