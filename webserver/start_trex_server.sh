#! /usr/bin/env bash

# set number of workers by TREX_GUNICORN_WORKERS envvar or the number of cores up to a limit of 4
workers=$(python3 -c "import os; print(os.getenv('TREX_GUNICORN_WORKERS', min(len(os.sched_getaffinity(0))+1,4)))")
source /usr/local/share/trex_server/venv/bin/activate
gunicorn -b 0.0.0.0:7100 --name "trex_server" --workers $workers --threads 3 "batch_rest_server:create_app()"