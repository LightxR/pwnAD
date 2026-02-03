"""
ADCS (Active Directory Certificate Services) web routes for pwnAD.
Provides web interface for CA enumeration and ESC vulnerability detection.
"""

import logging

from flask import Blueprint, render_template, request, current_app, jsonify

from pwnAD.lib.adcs import (
    get_certificate_templates, get_enrollment_services, analyze_adcs,
    get_oid_to_group_links, ESC_DEFINITIONS
)

adcs_bp = Blueprint('adcs', __name__)


def _get_conn():
    return current_app.config['LDAP_CONNECTION']


def _base_context(active_page='adcs'):
    """Common template context."""
    conn = _get_conn()
    return {
        'domain': conn.domain,
        'dc_ip': conn.target,
        'session_user': getattr(conn, 'ldap_user', '') or getattr(conn, 'user', ''),
        'active_page': active_page,
    }


@adcs_bp.route('/adcs')
def adcs_view():
    """Main ADCS view with CAs and templates."""
    conn = _get_conn()
    ctx = _base_context('adcs')

    # Query parameters
    selected_ca = request.args.get('ca', '').strip()
    vulnerable_only = request.args.get('vulnerable', '').lower() == 'true'
    enabled_only = request.args.get('enabled', '').lower() == 'true'

    ctx['selected_ca'] = selected_ca
    ctx['vulnerable_only'] = vulnerable_only
    ctx['enabled_only'] = enabled_only
    ctx['cas'] = []
    ctx['templates'] = []
    ctx['summary'] = {
        'total_templates': 0,
        'vulnerable_templates': 0,
        'critical_templates': 0,
        'total_cas': 0,
        'enrollable_templates': 0,
    }
    ctx['error'] = None

    try:
        # Perform full ADCS analysis
        result = analyze_adcs(conn, vulnerable_only=False)

        ctx['cas'] = result['cas']
        all_templates = result['templates']
        ctx['summary'] = result['summary']

        # Filter by CA if selected
        if selected_ca:
            ca_entry = next((ca for ca in ctx['cas'] if ca.name == selected_ca), None)
            if ca_entry:
                ca_template_names = ca_entry.certificate_templates
                all_templates = [t for t in all_templates if t.name in ca_template_names]

        # Filter enabled only (templates that are enabled on at least one CA)
        if enabled_only:
            all_templates = [t for t in all_templates if len(t.enabled_on_cas) > 0]

        # Filter vulnerable only
        if vulnerable_only:
            all_templates = [t for t in all_templates if t.is_vulnerable]

        # Sort: vulnerable first, then by name
        all_templates.sort(key=lambda t: (0 if t.is_vulnerable else 1, t.name))

        ctx['templates'] = all_templates

    except Exception as e:
        logging.error(f"Error loading ADCS data: {e}")
        ctx['error'] = f"Error loading ADCS data: {str(e)}"

    # HTMX partial response
    if request.headers.get('HX-Request'):
        return render_template('partials/adcs_template_list.html', **ctx)

    return render_template('adcs.html', **ctx)


@adcs_bp.route('/adcs/template/<name>')
def template_detail(name):
    """Get detailed information about a certificate template."""
    conn = _get_conn()
    ctx = _base_context('adcs')

    ctx['template'] = None
    ctx['error'] = None

    try:
        # Get OID links for ESC13
        oid_links = get_oid_to_group_links(conn)

        # Get all templates
        templates = get_certificate_templates(conn, parse_sd=True)

        # Find the requested template
        template = next((t for t in templates if t.name == name), None)

        if template:
            # Detect vulnerabilities
            template.detect_vulnerabilities(conn, oid_links)

            # Get CAs and map
            cas = get_enrollment_services(conn)
            for ca in cas:
                if template.name in ca.certificate_templates:
                    template.enabled_on_cas.append(ca.name)

            ctx['template'] = template
        else:
            ctx['error'] = f"Template '{name}' not found"

    except Exception as e:
        logging.error(f"Error loading template {name}: {e}")
        ctx['error'] = str(e)

    return render_template('partials/adcs_template_detail.html', **ctx)


@adcs_bp.route('/api/adcs/summary')
def api_adcs_summary():
    """API endpoint returning ADCS summary statistics."""
    conn = _get_conn()

    try:
        result = analyze_adcs(conn, vulnerable_only=False)

        # Count vulnerabilities by type
        vuln_by_type = {}
        for template in result['templates']:
            for vuln in template.vulnerabilities:
                vuln_id = vuln['id']
                vuln_by_type[vuln_id] = vuln_by_type.get(vuln_id, 0) + 1

        return jsonify({
            'success': True,
            'summary': result['summary'],
            'vulnerabilities_by_type': vuln_by_type,
            'cas': [
                {
                    'name': ca.name,
                    'dns_hostname': ca.dns_hostname,
                    'template_count': len(ca.certificate_templates)
                }
                for ca in result['cas']
            ]
        })

    except Exception as e:
        logging.error(f"API error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@adcs_bp.route('/api/adcs/templates')
def api_adcs_templates():
    """API endpoint returning all templates with vulnerability info."""
    conn = _get_conn()
    vulnerable_only = request.args.get('vulnerable', '').lower() == 'true'
    ca_filter = request.args.get('ca', '').strip()

    try:
        result = analyze_adcs(conn, vulnerable_only=False)
        templates = result['templates']

        # Filter by CA
        if ca_filter:
            ca_entry = next((ca for ca in result['cas'] if ca.name == ca_filter), None)
            if ca_entry:
                ca_templates = ca_entry.certificate_templates
                templates = [t for t in templates if t.name in ca_templates]

        # Filter vulnerable
        if vulnerable_only:
            templates = [t for t in templates if t.is_vulnerable]

        return jsonify({
            'success': True,
            'templates': [t.to_dict() for t in templates],
            'count': len(templates)
        })

    except Exception as e:
        logging.error(f"API error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@adcs_bp.route('/api/adcs/cas')
def api_adcs_cas():
    """API endpoint returning all Certificate Authorities."""
    conn = _get_conn()

    try:
        cas = get_enrollment_services(conn)
        return jsonify({
            'success': True,
            'cas': [ca.to_dict() for ca in cas],
            'count': len(cas)
        })

    except Exception as e:
        logging.error(f"API error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500
