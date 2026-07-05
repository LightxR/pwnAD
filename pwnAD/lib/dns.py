import logging
import struct
import ipaddress
import ldap3
from typing import Dict, Any, Literal


# DNS Record Type constants from MS-DNSP specification
DNS_RECORD_TYPE = {
    "ZERO": 0x0000,
    "A": 0x0001,
    "NS": 0x0002,
    "CNAME": 0x0005,
    "SOA": 0x0006,
    "PTR": 0x000C,
    "MX": 0x000F,
    "TXT": 0x0010,
    "AAAA": 0x001C,
    "SRV": 0x0021,
}

# Reverse mapping for lookup
DNS_TYPE_CODE = {v: k for k, v in DNS_RECORD_TYPE.items()}


class DNSRecord:
    """
    DNS Record structure for Active Directory DNS operations.
    Based on MS-DNSP specification.
    """

    def __init__(self, record_data: bytes = None):
        self.data_length = 0
        self.record_type = 0
        self.version = 5
        self.rank = 0xF0  # Zone authoritative
        self.flags = 0
        self.serial = 0
        self.ttl_seconds = 300
        self.reserved = 0
        self.timestamp = 0
        self.data = b""

        if record_data:
            self.from_bytes(record_data)

    def from_bytes(self, data: bytes):
        """Parse DNS record from the AD dnsRecord (MS-DNSP DNS_RECORD) blob.

        Field layout (24-byte header, mixed endianness): DataLength<H, Type<H,
        Version(byte), Rank(byte), Flags<H, Serial<L, TtlSeconds>L (big-endian),
        Reserved<L, TimeStamp<L, then Data.
        """
        if len(data) < 24:
            raise ValueError("DNS record data too short")

        self.data_length, self.record_type = struct.unpack("<HH", data[0:4])
        self.version = data[4]
        self.rank = data[5]
        (self.flags,) = struct.unpack("<H", data[6:8])
        (self.serial,) = struct.unpack("<L", data[8:12])
        (self.ttl_seconds,) = struct.unpack(">L", data[12:16])
        (self.reserved,) = struct.unpack("<L", data[16:20])
        (self.timestamp,) = struct.unpack("<L", data[20:24])

        self.data = data[24 : 24 + self.data_length]

    def to_bytes(self) -> bytes:
        """Serialize DNS record to the AD dnsRecord (MS-DNSP DNS_RECORD) blob."""
        header = (
            struct.pack("<HH", self.data_length, self.record_type)
            + struct.pack("BB", self.version, self.rank)
            + struct.pack("<H", self.flags)
            + struct.pack("<L", self.serial)
            + struct.pack(">L", self.ttl_seconds)  # big-endian per MS-DNSP
            + struct.pack("<L", self.reserved)
            + struct.pack("<L", self.timestamp)
        )
        return header + self.data

    def from_dict(
        self,
        dns_type: Literal["A", "AAAA", "CNAME", "MX", "PTR", "SRV", "TXT", "NS"],
        record_data: str,
        serial: int,
        ttl: int = 300,
        preference: int = 10,
        priority: int = 0,
        weight: int = 100,
        port: int = 80,
    ):
        """
        Create DNS record from dictionary parameters.

        Args:
            dns_type: Type of DNS record (A, AAAA, CNAME, MX, PTR, SRV, TXT)
            record_data: The record data (IP, hostname, or text)
            serial: Serial number from SOA record
            ttl: Time to live in seconds
            preference: Preference for MX records
            priority: Priority for SRV records
            weight: Weight for SRV records
            port: Port for SRV records
        """
        self.record_type = DNS_RECORD_TYPE.get(dns_type, 0)
        self.serial = serial
        self.ttl_seconds = ttl

        if dns_type == "A":
            # IPv4 address
            ip = ipaddress.IPv4Address(record_data)
            self.data = ip.packed
            self.data_length = 4

        elif dns_type == "AAAA":
            # IPv6 address
            ip = ipaddress.IPv6Address(record_data)
            self.data = ip.packed
            self.data_length = 16

        elif dns_type in ["CNAME", "PTR", "NS"]:
            # DNS name encoding
            self.data = self._encode_dns_name(record_data)
            self.data_length = len(self.data)

        elif dns_type == "MX":
            # MX record: preference (2 bytes, big-endian) + DNS name
            self.data = struct.pack(">H", preference) + self._encode_dns_name(record_data)
            self.data_length = len(self.data)

        elif dns_type == "SRV":
            # SRV record: priority, weight, port (big-endian) + target
            self.data = (
                struct.pack(">HHH", priority, weight, port)
                + self._encode_dns_name(record_data)
            )
            self.data_length = len(self.data)

        elif dns_type == "TXT":
            # TXT record: length byte + string data
            txt_data = record_data.encode("utf-8")
            self.data = struct.pack("B", len(txt_data)) + txt_data
            self.data_length = len(self.data)

        else:
            raise ValueError(f"Unsupported DNS record type: {dns_type}")

    def _encode_dns_name(self, name: str) -> bytes:
        """
        Encode a DNS name as an MS-DNSP DNS_COUNT_NAME.

        Layout: <cchNameLength><cLabelCount><label...><0x00> where cchNameLength
        is the byte length of the label section (including the terminating null)
        and each label is preceded by its length as a byte.
        """
        labels = [label for label in name.rstrip(".").split(".") if label]
        raw = b""
        for label in labels:
            label_bytes = label.encode("utf-8")
            raw += struct.pack("B", len(label_bytes)) + label_bytes
        raw += b"\x00"  # terminating null label
        return struct.pack("BB", len(raw), len(labels)) + raw

    def _decode_dns_name(self, data: bytes, offset: int = 0) -> tuple[str, int]:
        """
        Decode an MS-DNSP DNS_COUNT_NAME starting at ``offset``.
        Returns (name, bytes_consumed_from_offset).
        """
        # data[offset]   = byte length of the label section
        # data[offset+1] = label count (unused when parsing, labels are null-terminated)
        labels = []
        pos = offset + 2
        while pos < len(data):
            length = data[pos]
            pos += 1
            if length == 0:
                break
            if length >= 192:  # Compression pointer (not used in stored records)
                raise ValueError("DNS name compression not supported")
            labels.append(data[pos : pos + length].decode("utf-8"))
            pos += length

        return ".".join(labels), pos - offset

    def to_dict(self) -> Dict[str, Any]:
        """Convert DNS record to dictionary format."""
        result = {
            "type": DNS_TYPE_CODE.get(self.record_type, "UNKNOWN"),
            "serial": self.serial,
            "ttl": self.ttl_seconds,
        }

        dns_type = DNS_TYPE_CODE.get(self.record_type, "UNKNOWN")

        try:
            if dns_type == "A":
                result["data"] = str(ipaddress.IPv4Address(self.data))
            elif dns_type == "AAAA":
                result["data"] = str(ipaddress.IPv6Address(self.data))
            elif dns_type in ["CNAME", "PTR", "NS"]:
                result["data"], _ = self._decode_dns_name(self.data)
            elif dns_type == "MX":
                preference = struct.unpack(">H", self.data[:2])[0]
                hostname, _ = self._decode_dns_name(self.data, 2)
                result["preference"] = preference
                result["data"] = hostname
            elif dns_type == "SRV":
                priority, weight, port = struct.unpack(">HHH", self.data[:6])
                target, _ = self._decode_dns_name(self.data, 6)
                result["priority"] = priority
                result["weight"] = weight
                result["port"] = port
                result["data"] = target
            elif dns_type == "TXT":
                length = self.data[0]
                result["data"] = self.data[1 : 1 + length].decode("utf-8")
            else:
                result["data"] = self.data.hex()
        except Exception as e:
            logging.error(f"Error parsing DNS record data: {e}")
            result["data"] = self.data.hex()

        return result


def get_dns_zones(conn) -> tuple[str, str]:
    """
    Get DNS zone distinguished names for the domain.

    Args:
        conn: LDAP connection object

    Returns:
        Tuple of (domain_zone_dn, forest_zone_dn)
    """
    domain_parts = conn.domain.split(".")
    domain_dc = ",".join([f"DC={part}" for part in domain_parts])

    domain_zone_dn = f"DC=DomainDnsZones,{domain_dc}"
    forest_zone_dn = f"DC=ForestDnsZones,{domain_dc}"

    return domain_zone_dn, forest_zone_dn


def get_zone_dn(conn, zone: str, forest: bool = False) -> str:
    """
    Get the DN for a specific DNS zone.

    Args:
        conn: LDAP connection object
        zone: Zone name (e.g., "domain.local")
        forest: If True, uses ForestDnsZones instead of DomainDnsZones

    Returns:
        Zone distinguished name
    """
    # Get domain DN from baseDN (e.g., "DC=robco,DC=corp")
    naming_context = "," + conn._baseDN

    # Determine zone type
    zone_type = "ForestDnsZones" if forest else "DomainDnsZones"

    # DC={zone},CN=MicrosoftDNS,DC={zone_type}{naming_context}
    # Example: DC=robco.corp,CN=MicrosoftDNS,DC=DomainDnsZones,DC=robco,DC=corp
    zone_dn = f"DC={zone},CN=MicrosoftDNS,DC={zone_type}{naming_context}"

    logging.debug(f"Constructed zone DN: {zone_dn}")
    return zone_dn


def get_soa_serial(conn, zone: str) -> tuple[int, str]:
    """
    Get the serial number from the SOA record of a DNS zone.
    Tries multiple zone locations and returns the serial + zone DN that works.

    Args:
        conn: LDAP connection object
        zone: DNS zone name

    Returns:
        Tuple of (serial number, zone_dn that works)
    """
    naming_context = "," + conn._baseDN

    # Try different zone types in order of likelihood
    zone_types = ["DomainDnsZones", "ForestDnsZones"]

    for zone_type in zone_types:
        zone_dn = f"DC={zone},CN=MicrosoftDNS,DC={zone_type}{naming_context}"
        soa_dn = f"DC=@,{zone_dn}"

        logging.debug(f"Trying SOA at: {soa_dn}")

        try:
            conn.search(
                search_base=soa_dn,
                search_filter="(objectClass=dnsNode)",
                search_scope=ldap3.BASE,
                attributes=["dnsRecord"],
            )

            if conn._ldap_connection.entries:
                soa_entry = conn._ldap_connection.entries[0]
                if "dnsRecord" in soa_entry and soa_entry["dnsRecord"].raw_values:
                    # Parse DNS records to find SOA (usually the first one)
                    for record_data in soa_entry["dnsRecord"].raw_values:
                        try:
                            dns_record = DNSRecord(record_data)
                            # SOA record type is 0x0006
                            if dns_record.record_type == DNS_RECORD_TYPE.get("SOA", 0x0006):
                                logging.debug(f"Found SOA in {zone_type} with serial: {dns_record.serial}")
                                return dns_record.serial, zone_dn
                            # If not SOA, use the serial from any record
                            logging.debug(f"Using serial from record type {dns_record.record_type} in {zone_type}: {dns_record.serial}")
                            return dns_record.serial, zone_dn
                        except Exception as e:
                            logging.debug(f"Error parsing DNS record: {e}")
                            continue

        except Exception as e:
            logging.debug(f"SOA not found in {zone_type}: {e}")
            continue

    # If no SOA found anywhere, use default
    import time
    default_serial = int(time.time())
    # Default to DomainDnsZones
    default_zone_dn = f"DC={zone},CN=MicrosoftDNS,DC=DomainDnsZones{naming_context}"
    logging.warning(f"No SOA record found in any zone type, using default serial: {default_serial}")
    return default_serial, default_zone_dn
