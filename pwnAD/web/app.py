import logging
from pwnAD.web import create_app


def start_web(connection, host='127.0.0.1', port=5000):
    """Start the Flask web server with an authenticated LDAP connection."""
    app = create_app(connection)

    logging.info(f"Starting pwnAD web server")
    logging.info("Press CTRL+C to stop the server")

    try:
        from waitress import serve
        # Serve with waitress - this call blocks until server shutdown
        serve(
            app,
            host=host,
            port=port,
            threads=4,
            channel_timeout=300,
            _quiet=False  # Enable request logging
        )
    except ImportError:
        logging.warning("[!] Waitress not installed, falling back to Flask development server")
        logging.warning("[!] Install waitress for production use: pip install waitress")
        app.run(host=host, port=port, debug=False, use_reloader=False)
