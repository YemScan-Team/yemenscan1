# -*- coding: utf-8 -*-
"""
Target Prioritizer for YemenScan.
Guarantees that the primary user-entered target domain/URL is always positioned
at the absolute top (index 0, line 1) of all tool outputs, scan target lists,
and API responses so that it is audited first and foremost.
"""

from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Optional


def get_url_priority(u: str, target_domain: str) -> Tuple[int, str]:
    """
    Computes priority tuple for sorting URLs.
    Lower number = higher priority (tested first).
    0: https://{target_domain} (default port)
    1: http://{target_domain} (default port)
    2: https://{target_domain}:{custom_port}
    3: http://{target_domain}:{custom_port}
    4: https://www.{target_domain}
    5: http://www.{target_domain}
    10: https://*.{target_domain} (subdomains)
    11: http://*.{target_domain} (subdomains)
    20: Other IP / third party hosts
    """
    if not u or not isinstance(u, str):
        return (99, "")

    u_clean = u.strip()
    clean_dom = target_domain.strip().lower() if target_domain else ""
    if not clean_dom:
        return (0 if u_clean.startswith("https://") else 1, u_clean)

    try:
        url_with_scheme = u_clean if "://" in u_clean else f"http://{u_clean}"
        parsed = urlparse(url_with_scheme)
        host = (parsed.hostname or "").lower()
        scheme = (parsed.scheme or "http").lower()
        port = parsed.port

        is_default_port = not port or (scheme == "https" and port == 443) or (scheme == "http" and port == 80)

        if host == clean_dom:
            if is_default_port:
                return (0 if scheme == "https" else 1, u_clean)
            return (2 if scheme == "https" else 3, u_clean)
        elif host == f"www.{clean_dom}":
            if is_default_port:
                return (4 if scheme == "https" else 5, u_clean)
            return (6 if scheme == "https" else 7, u_clean)
        elif host.endswith(f".{clean_dom}"):
            return (10 if scheme == "https" else 11, u_clean)
        else:
            return (20 if scheme == "https" else 21, u_clean)
    except Exception:
        return (50, u_clean)


def prioritize_urls(urls: List[str], target_domain: str) -> List[str]:
    """
    Sorts a list of URLs placing the primary target domain at the very top.
    Preserves uniqueness while maintaining the priority order.
    """
    if not urls:
        return []

    # Deduplicate while preserving relative order
    seen = set()
    unique_urls = []
    for u in urls:
        if u and u.strip() and u.strip() not in seen:
            seen.add(u.strip())
            unique_urls.append(u.strip())

    return sorted(unique_urls, key=lambda u: get_url_priority(u, target_domain))


def get_host_priority(h: str, target_domain: str) -> Tuple[int, str]:
    """Computes priority for sorting hostnames/subdomains."""
    if not h or not isinstance(h, str):
        return (99, "")

    clean_h = h.strip().lower()
    clean_dom = target_domain.strip().lower() if target_domain else ""
    if not clean_dom:
        return (0, clean_h)

    if clean_h == clean_dom:
        return (0, clean_h)
    elif clean_h == f"www.{clean_dom}":
        return (1, clean_h)
    elif clean_h.endswith(f".{clean_dom}"):
        return (2, clean_h)
    else:
        return (3, clean_h)


def prioritize_hosts(hosts: List[str], target_domain: str, include_root: bool = True) -> List[str]:
    """
    Sorts hostnames/subdomains list.
    If include_root is True (default for backward compatibility with general target lists),
    places root domain at index 0, followed by www.{target_domain}, then other subdomains.
    If include_root is False (explicitly passed by Subfinder stage and discovery endpoints),
    the root domain is strictly excluded from the returned subdomains list.
    """
    clean_dom = target_domain.strip().lower() if target_domain else ""
    if "://" in clean_dom:
        clean_dom = clean_dom.split("://", 1)[1]
    clean_dom = clean_dom.split("/", 1)[0].split(":", 1)[0].rstrip(".")

    if not hosts:
        if include_root and clean_dom:
            return [clean_dom]
        return []

    seen = set()
    unique_hosts = []
    for h in hosts:
        if not h or not isinstance(h, str):
            continue
        h_clean = h.strip().lower().rstrip(".")
        if not h_clean:
            continue
        if not include_root and clean_dom and h_clean == clean_dom:
            continue
        if h_clean not in seen:
            seen.add(h_clean)
            unique_hosts.append(h_clean)

    if include_root and clean_dom and clean_dom not in seen:
        unique_hosts.insert(0, clean_dom)

    return sorted(unique_hosts, key=lambda h: get_host_priority(h, target_domain))


def get_port_priority(p: str, target_domain: str) -> Tuple[int, str]:
    """Computes priority for host:port entries."""
    if not p or not isinstance(p, str):
        return (99, "")

    clean_p = p.strip()
    clean_dom = target_domain.strip().lower() if target_domain else ""
    if not clean_dom:
        return (0, clean_p)

    parts = clean_p.split(":")
    host = parts[0].lower()
    port = parts[1] if len(parts) > 1 else ""

    if host == clean_dom:
        if port == "443":
            return (0, clean_p)
        elif port == "80":
            return (1, clean_p)
        elif port in ["8443", "8080"]:
            return (2, clean_p)
        else:
            return (3, clean_p)
    elif host == f"www.{clean_dom}":
        if port == "443":
            return (4, clean_p)
        elif port == "80":
            return (5, clean_p)
        else:
            return (6, clean_p)
    elif host.endswith(f".{clean_dom}"):
        if port in ["443", "8443"]:
            return (10, clean_p)
        elif port in ["80", "8080"]:
            return (11, clean_p)
        else:
            return (12, clean_p)
    else:
        return (20, clean_p)


def prioritize_ports(ports: List[str], target_domain: str) -> List[str]:
    """Sorts ports.txt entries placing target_domain:443 and target_domain:80 at the very top."""
    if not ports:
        return []

    seen = set()
    unique_ports = []
    for p in ports:
        if p and p.strip() and p.strip() not in seen:
            seen.add(p.strip())
            unique_ports.append(p.strip())

    return sorted(unique_ports, key=lambda p: get_port_priority(p, target_domain))


def prioritize_dict_records(records: List[Dict[str, Any]], target_domain: str, key: str = "url") -> List[Dict[str, Any]]:
    """Sorts dictionaries (such as live_web_services, api_endpoints) prioritizing target_domain."""
    if not records:
        return []

    def _sorter(item: Dict[str, Any]) -> Tuple[int, str]:
        val = item.get(key) or item.get("host") or ""
        return get_url_priority(str(val), target_domain)

    return sorted(records, key=_sorter)
