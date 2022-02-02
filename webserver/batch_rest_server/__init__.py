from flask_cors import CORS
from batch_rest_server import config
from flask import redirect
import connexion

app = connexion.FlaskApp(__name__, specification_dir="api")  # connexion app
app.add_api('openapi.yml', options=config.SWAGGER_UI)

# TODO remove CORS later
CORS(app.app, resources={r"/api/*": {"origins": "*"}})


@app.route('/')
def home():
    return redirect('/v1/ui')


def create_app():
    envvars = dict(
        env.get(name_transform=lambda s: config.PREFIX + s.upper())
        for env in config._SCHEMA)

    app.app.config.update(**envvars)
    print(envvars)
    return app


if __name__ == '__main__':
    create_app()
