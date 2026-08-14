"""WSGI entrypoint for the reference receiver deployment."""

import os

from catchme.receiver import create_receiver_app

app = create_receiver_app(os.environ.get("CATCHME_SERVER_DB", "/data/server.db"))
