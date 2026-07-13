"""Shared helpers for pwnAD web routes."""

import math

from flask import current_app, request


DEFAULT_PAGE_SIZE = 50


def get_conn():
    return current_app.config['LDAP_CONNECTION']


def base_context(active_page=''):
    conn = get_conn()
    return {
        'domain': conn.domain,
        'dc_ip': conn.target,
        'session_user': getattr(conn, 'ldap_user', '') or getattr(conn, 'user', ''),
        'active_page': active_page,
    }


def paginate(items, page=None, per_page=None):
    if page is None:
        page = request.args.get('page', 1, type=int)
    if per_page is None:
        per_page = request.args.get('size', DEFAULT_PAGE_SIZE, type=int)
    per_page = min(per_page, 200)
    page = max(page, 1)
    total = len(items)
    total_pages = max(math.ceil(total / per_page), 1)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    end = start + per_page
    return {
        'items': items[start:end],
        'page': page,
        'per_page': per_page,
        'total': total,
        'total_pages': total_pages,
        'has_prev': page > 1,
        'has_next': page < total_pages,
    }
