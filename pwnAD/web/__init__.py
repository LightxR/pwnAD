import logging

from flask import Flask


def create_app(ldap_connection):
    """Flask application factory.

    Args:
        ldap_connection: Authenticated LDAPConnection instance.
    """
    app = Flask(__name__)
    app.config['LDAP_CONNECTION'] = ldap_connection

    @app.before_request
    def check_ldap_connection():
        """Check LDAP connection health before each request and rebind if needed."""
        conn = app.config['LDAP_CONNECTION']
        if not conn.is_connected():
            logging.info("[*] LDAP connection not active, attempting rebind...")
            conn.rebind()

    from pwnAD.web.routes.browse import browse_bp
    app.register_blueprint(browse_bp)

    from pwnAD.web.routes.actions import actions_bp
    app.register_blueprint(actions_bp)

    from pwnAD.web.routes.dacl import dacl_bp
    app.register_blueprint(dacl_bp)

    from pwnAD.web.routes.dns import dns_bp
    app.register_blueprint(dns_bp)

    from pwnAD.web.routes.shadow import shadow_bp
    app.register_blueprint(shadow_bp)

    from pwnAD.web.routes.attack import attack_bp
    app.register_blueprint(attack_bp)

    return app
