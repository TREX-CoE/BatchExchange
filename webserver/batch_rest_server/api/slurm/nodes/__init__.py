from sys import stderr
import flask as f
import subprocess


def setState():
    data = f.request.get_json()
    command = "scontrol update nodename={} state={} reason={}".format(
        ",".join(data["nodes"]), data["state"], data["reason"])
    process = subprocess.Popen(command.split(),
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
    output, err = process.communicate()

    return 200, {"data": output, "errors": err}
