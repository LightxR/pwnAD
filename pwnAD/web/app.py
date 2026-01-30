import logging
from pwnAD.web import create_app


def start_web(connection, host='127.0.0.1', port=5000):
    """Start the Flask web server with an authenticated LDAP connection."""
    app = create_app(connection)
    logging.info(f"[*] Starting web interface on http://{host}:{port}")
    app.run(host=host, port=port, debug=False, use_reloader=False)
