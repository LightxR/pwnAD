"""
BloodHound CE export for pwnAD — delegates to bloodhound-ce (BloodHound.py).

Wraps the bloodhound-ce package to reuse pwnAD's connection credentials
and provide a consistent interface for both CLI and web usage.

Install: pip install bloodhound-ce
"""
import datetime
import glob
import ipaddress
import logging
import os
import zipfile


def _is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _build_auth(conn):
    """Build a BloodHound ADAuthentication from a pwnAD LDAPConnection."""
    from bloodhound.ad.authentication import ADAuthentication

    return ADAuthentication(
        username=conn.ldap_user or '',
        password=conn.ldap_pass or '',
        domain=conn.domain or '',
        lm_hash=conn.lmhash or '',
        nt_hash=conn.nthash or '',
        aeskey=conn.aesKey or '',
    )


def _run_collection(conn, output_dir='.', prefix='', collect=None,
                    num_workers=10, disable_pooling=False, exclude_dcs=False,
                    zip_output=True, nameserver=None):
    """Run BloodHound collection using bloodhound-ce.

    Args:
        conn: pwnAD LDAPConnection with valid credentials
        output_dir: directory for output files
        prefix: filename prefix
        collect: collection methods (None = DCOnly for LDAP-only)
        num_workers: number of worker threads for SMB collection
        disable_pooling: disable connection pooling
        exclude_dcs: exclude domain controllers from computer enum
        zip_output: create a zip file from the JSON output
        nameserver: DNS server for hostname resolution (default: DC IP)

    Returns:
        str: path to output zip (if zip_output) or output_dir
    """
    from bloodhound import BloodHound
    from bloodhound.ad.domain import AD

    auth = _build_auth(conn)

    use_ldaps = getattr(conn, '_do_tls', False)
    dns_server = nameserver or conn.target
    ad = AD(auth=auth, domain=conn.domain, nameserver=dns_server,
            use_ldaps=use_ldaps)

    dc_host = conn.target

    try:
        ad.dns_resolve(domain=conn.domain)
    except Exception:
        logging.debug("DNS resolution failed")

    if not ad.dcs():
        if _is_ip(dc_host):
            # Try reverse DNS to get FQDN (BH.py needs hostnames, not IPs)
            try:
                from dns import reversename
                rev = reversename.from_address(dc_host)
                ans = ad.dnsresolver.resolve(rev, 'PTR')
                dc_fqdn = str(ans[0]).rstrip('.')
                ad.override_dc(dc_fqdn)
                logging.debug("Reverse DNS: %s -> %s", dc_host, dc_fqdn)
            except Exception:
                ad.override_dc(dc_host)
                logging.debug("No reverse DNS, using IP directly: %s", dc_host)
        else:
            ad.override_dc(dc_host)

    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + "_"

    file_prefix = prefix if prefix else None

    if collect is None:
        collect = {
            'group', 'objectprops', 'acl', 'trusts', 'container',
        }

    orig_cwd = os.getcwd()
    abs_output_dir = os.path.abspath(output_dir)
    os.makedirs(abs_output_dir, exist_ok=True)

    try:
        os.chdir(abs_output_dir)

        bh = BloodHound(ad)
        bh.connect()

        # BH.py can't DNS-resolve an IP as a hostname — establish LDAP directly
        if _is_ip(bh.pdc.hostname) and bh.pdc.ldap is None:
            ldap_conn = ad.auth.getLDAPConnection(
                hostname=bh.pdc.hostname,
                ip=bh.pdc.hostname,
                baseDN=ad.baseDN,
                protocol=ad.ldap_default_protocol,
            )
            bh.pdc.ldap = ldap_conn
            bh.pdc.resolverldap = ad.auth.getLDAPConnection(
                hostname=bh.pdc.hostname,
                ip=bh.pdc.hostname,
                baseDN=ad.baseDN,
                protocol=ad.ldap_default_protocol,
            )

        bh.run(
            collect=collect,
            num_workers=num_workers,
            disable_pooling=disable_pooling,
            timestamp=timestamp,
            computerfile='',
            cachefile=None,
            exclude_dcs=exclude_dcs,
            fileNamePrefix=file_prefix,
        )
    finally:
        os.chdir(orig_cwd)

    if zip_output:
        return _zip_results(abs_output_dir, timestamp, file_prefix)

    return abs_output_dir


def _zip_results(output_dir, timestamp, file_prefix=None):
    """Zip all JSON files matching the timestamp into a single archive."""
    if file_prefix:
        glob_prefix = f"{file_prefix}_{timestamp}"
    else:
        glob_prefix = timestamp
    pattern = os.path.join(output_dir, f"{glob_prefix}*.json")
    json_files = glob.glob(pattern)

    if not json_files:
        all_json = glob.glob(os.path.join(output_dir, f"*{timestamp}*.json"))
        if all_json:
            json_files = all_json

    if not json_files:
        raise RuntimeError(f"No output files found matching {pattern}")

    zip_name = f"{glob_prefix}bloodhound.zip"
    zip_path = os.path.join(output_dir, zip_name)

    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fpath in json_files:
            zf.write(fpath, os.path.basename(fpath))

    for fpath in json_files:
        os.remove(fpath)

    total = len(json_files)
    logging.info(f"[*] BloodHound export complete: {total} files → {zip_path}")
    return zip_path


# Collection presets
COLLECT_DCONLY = {'group', 'objectprops', 'acl', 'trusts', 'container'}
COLLECT_DEFAULT = {'group', 'localadmin', 'session', 'trusts'}
COLLECT_ALL = {
    'group', 'localadmin', 'session', 'trusts',
    'objectprops', 'acl', 'dcom', 'rdp', 'psremote', 'container',
}
