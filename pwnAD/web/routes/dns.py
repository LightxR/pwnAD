import logging

import ldap3
from flask import Blueprint, request, render_template, jsonify
from ldap3.utils.conv import escape_filter_chars

from pwnAD.lib.dns import DNSRecord, DNS_RECORD_TYPE, DNS_TYPE_CODE
from pwnAD.web.context import get_conn, base_context
from pwnAD.web.utils import LDAP_CONNECTION_ERRORS, ldap_search_with_retry

dns_bp = Blueprint('dns', __name__)


def _get_dns_zones(conn):
    """Find all DNS zones in AD."""
    zones = []
    naming_context = "," + conn._baseDN

    for zone_type in ["DomainDnsZones", "ForestDnsZones"]:
        search_base = f"CN=MicrosoftDNS,DC={zone_type}{naming_context}"
        try:
            response, _ = ldap_search_with_retry(
                conn, search_base, "(objectClass=dnsZone)",
                ["name", "distinguishedName"], ldap3.SUBTREE
            )
            for entry in response:
                if entry.get('type') != 'searchResEntry':
                    continue
                zone_name = entry['attributes'].get('name', '')
                if zone_name and zone_name != 'RootDNSServers':
                    zones.append({
                        'name': zone_name,
                        'dn': entry['dn'],
                        'type': zone_type,
                    })
        except Exception as e:
            logging.debug(f"Error searching DNS zones in {zone_type}: {e}")

    return zones


def _get_dns_records(conn, zone_dn):
    """Get all DNS records in a zone."""
    records = []
    try:
        response, _ = ldap_search_with_retry(
            conn, zone_dn, "(objectClass=dnsNode)",
            ["name", "dnsRecord", "distinguishedName", "dNSTombstoned"],
            ldap3.SUBTREE
        )
        for entry in response:
            if entry.get('type') != 'searchResEntry':
                continue
            name = entry['attributes'].get('name', '')
            tombstoned = entry['attributes'].get('dNSTombstoned', False)
            if tombstoned:
                continue
            dn = entry['dn']
            raw_records = entry.get('raw_attributes', {}).get('dnsRecord', [])

            for raw in raw_records:
                try:
                    dns_rec = DNSRecord(raw)
                    rec_dict = dns_rec.to_dict()
                    rec_dict['name'] = name
                    rec_dict['dn'] = dn
                    records.append(rec_dict)
                except Exception as e:
                    logging.debug(f"Error parsing DNS record for {name}: {e}")

    except Exception as e:
        logging.error(f"Error fetching DNS records: {e}")

    return records


@dns_bp.route('/dns')
def dns_view():
    conn = get_conn()
    ctx = base_context('dns')

    zones = _get_dns_zones(conn)
    ctx['zones'] = zones

    selected_zone = request.args.get('zone', '').strip()
    ctx['selected_zone'] = selected_zone
    ctx['zone'] = selected_zone

    if selected_zone:
        # Find the zone DN
        zone_info = next((z for z in zones if z['name'] == selected_zone), None)
        if zone_info:
            ctx['records'] = _get_dns_records(conn, zone_info['dn'])
            ctx['zone_dn'] = zone_info['dn']
        else:
            ctx['records'] = []
            ctx['zone_dn'] = ''
    else:
        ctx['records'] = None
        ctx['zone_dn'] = ''

    ctx['dns_types'] = sorted([k for k in DNS_RECORD_TYPE.keys() if k != 'ZERO' and k != 'SOA'])

    return render_template('dns.html', **ctx)


@dns_bp.route('/dns/records')
def dns_records():
    conn = get_conn()
    zone = request.args.get('zone', '').strip()

    if not zone:
        return '<tr><td colspan="5" class="px-4 py-8 text-center text-neutral-500">Select a zone</td></tr>'

    zones = _get_dns_zones(conn)
    zone_info = next((z for z in zones if z['name'] == zone), None)
    if not zone_info:
        return '<tr><td colspan="5" class="px-4 py-8 text-center text-neutral-500">Zone not found</td></tr>'

    records = _get_dns_records(conn, zone_info['dn'])
    return render_template('partials/dns_records.html', records=records, zone=zone, zone_dn=zone_info['dn'])


@dns_bp.route('/dns/record/add', methods=['POST'])
def dns_record_add():
    conn = get_conn()
    zone = request.form.get('zone', '').strip()
    name = request.form.get('name', '').strip()
    dnstype = request.form.get('type', 'A').strip()
    data = request.form.get('data', '').strip()

    if not zone or not name or not data:
        return jsonify(success=False, message='Missing required fields'), 400

    try:
        ttl = int(request.form.get('ttl', '300') or '300')
    except ValueError:
        return jsonify(success=False, message='Invalid TTL'), 400

    try:
        from pwnAD.commands.add import dnsRecord
        dnsRecord(
            conn, name=name, data=data, dnstype=dnstype,
            zone=zone, ttl=ttl
        )
        return jsonify(success=True, message=f'DNS record {name} ({dnstype}) added')
    except Exception as e:
        logging.error(f"DNS record add error: {e}")
        return jsonify(success=False, message=str(e))


@dns_bp.route('/dns/record/remove', methods=['POST'])
def dns_record_remove():
    conn = get_conn()
    zone = request.form.get('zone', '').strip()
    name = request.form.get('name', '').strip()
    data = request.form.get('data', '').strip() or None
    dnstype = request.form.get('type', '').strip() or None

    if not zone or not name:
        return jsonify(success=False, message='Missing required fields'), 400

    try:
        from pwnAD.commands.remove import dnsRecord
        dnsRecord(conn, name=name, data=data, dnstype=dnstype, zone=zone)
        return jsonify(success=True, message=f'DNS record {name} removed')
    except Exception as e:
        logging.error(f"DNS record remove error: {e}")
        return jsonify(success=False, message=str(e))
