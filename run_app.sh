cd "$(dirname "$0")/.."
export FLASK_APP=toy_oauth_server.main
export FLASK_DEBUG=1

python3 -m flask run --port 8000