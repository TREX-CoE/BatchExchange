from sys import stderr
import flask as f
import subprocess


def setState():
    data = f.request.get_json()
    if not len(data["nodes"]):
        return 400, {"errors": "missing node names"}

    command = "scontrol update nodename={} state={} reason={}".format(
        ",".join(data["nodes"]), data["state"], data["reason"])
    process = subprocess.Popen(command.split(),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE,
                               encoding="UTF-8")
    output, err = process.communicate()

    return {"data": output, "errors": err}, 200
