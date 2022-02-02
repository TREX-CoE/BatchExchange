from pathlib import Path
import batch_rest_server.helper.envparser as ep
from batch_rest_server.helper.envparser.core import Env

PREFIX = "BATCH_"
P_MODULE = Path(__file__).parent.absolute()
API_VERSION = "v1"
# API_BASE = "api"
SWAGGER_UI = {
    "validatorUrl": None,
    "filter": "",
    "docExpansion": "list",
    "operationsSorter": "method",
    "tagsSorter": "alpha",
    "swagger_ui": True, #TODO make dynamic
    "urls": [{
        "name": "v1",
        "url": "/{}/openapi.json".format(API_VERSION)
    }],
    
}
path = str
_SCHEMA = [
    Env("SERVE_BACKEND", parser=ep.flag, default=True),
    Env("SERVE_SWAGGER", parser=ep.flag, default=True),
    Env("DEBUG", parser=ep.flag, default=False),
    Env("SERVER_PORT", default=7100),
    Env("SWAGGER_STATIC_DIR", parser=path, default=str(P_MODULE / "swagger")),
    Env("SWAGGER_UI", default=SWAGGER_UI),
]