"""Domain reconnaissance -- WHOIS, DNS, subdomains, tech detection, SSL."""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from osintrecon.core.config import Config

# Default subdomain wordlist for brute-force enumeration
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "smtp", "pop", "imap", "webmail", "ns1", "ns2",
    "dns", "mx", "vpn", "remote", "admin", "portal", "dev", "staging",
    "test", "api", "app", "cdn", "cloud", "git", "gitlab", "jenkins",
    "ci", "monitor", "status", "docs", "wiki", "blog", "shop", "store",
    "beta", "alpha", "demo", "sandbox", "internal", "intranet", "backup",
    "db", "database", "sql", "redis", "elastic", "search", "m", "mobile",
    "static", "assets", "img", "media", "files", "download", "upload",
    "auth", "sso", "login", "register", "oauth", "grafana", "prometheus",
    "kibana", "traefik", "proxy", "gateway", "lb", "node1", "node2",
]


class DomainModule:
    """Domain reconnaissance module.

    Args:
        config: Framework configuration.
    """

    def __init__(self, config: Optional["Config"] = None) -> None:
        self.config = config
        self._timeout = config.timeout if config else 15

    async def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform a WHOIS lookup on *domain*.

        Args:
            domain: The target domain.

        Returns:
            A dict with registrar, dates, name servers, and registrant info.
        """
        result: Dict[str, Any] = {"domain": domain}
        try:
            import whois

            w = whois.whois(domain)
            result["registrar"] = getattr(w, "registrar", None)
            result["creation_date"] = str(getattr(w, "creation_date", None))
            result["expiration_date"] = str(getattr(w, "expiration_date", None))
            result["updated_date"] = str(getattr(w, "updated_date", None))
            result["name_servers"] = getattr(w, "name_servers", [])
            result["status"] = getattr(w, "status", None)
            result["org"] = getattr(w, "org", None)
            result["country"] = getattr(w, "country", None)
        except ImportError:
            result["error"] = "python-whois not installed"
        except Exception as exc:
            result["error"] = str(exc)
        return result

    async def dns_records(self, domain: str) -> Dict[str, Any]:
        """Query A, AAAA, MX, NS, TXT, CNAME, and SOA records.

        Args:
            domain: The target domain.

        Returns:
            A dict mapping record type to a list of values.
        """
        records: Dict[str, Any] = {"domain": domain}
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

        try:
            import dns.resolver

            for rtype in record_types:
                try:
                    answers = dns.resolver.resolve(domain, rtype)
                    if rtype == "MX":
                        records[rtype] = [
                            {"priority": r.preference, "host": str(r.exchange).rstrip(".")}
                            for r in answers
                        ]
                    elif rtype == "SOA":
                        soa = answers[0]
                        records[rtype] = {
                            "mname": str(soa.mname),
                            "rname": str(soa.rname),
                            "serial": soa.serial,
                        }
                    else:
                        records[rtype] = [str(r).strip('"') for r in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                    records[rtype] = []
        except ImportError:
            # Fallback: basic A-record lookup via socket
            try:
                ips = socket.getaddrinfo(domain, None)
                records["A"] = list({addr[4][0] for addr in ips if addr[0] == socket.AF_INET})
                records["AAAA"] = list({addr[4][0] for addr in ips if addr[0] == socket.AF_INET6})
            except socket.gaierror:
                records["error"] = "DNS resolution failed"
        except Exception as exc:
            records["error"] = str(exc)

        return records

    async def subdomain_enum(
        self,
        domain: str,
        wordlist: Optional[List[str]] = None,
        max_concurrent: int = 50,
    ) -> Dict[str, Any]:
        """Brute-force subdomain enumeration via DNS resolution.

        Args:
            domain: The base domain.
            wordlist: Subdomain prefixes to test. Defaults to a built-in list.
            max_concurrent: Concurrency cap.

        Returns:
            A dict with ``found`` (list of resolved subdomains) and ``total_checked``.
        """
        wordlist = wordlist or DEFAULT_SUBDOMAINS
        found: List[Dict[str, Any]] = []
        sem = asyncio.Semaphore(max_concurrent)

        async def _resolve(sub: str) -> Optional[Dict[str, Any]]:
            fqdn = f"{sub}.{domain}"
            async with sem:
                loop = asyncio.get_event_loop()
                try:
                    addrs = await loop.run_in_executor(
                        None, socket.getaddrinfo, fqdn, None
                    )
                    ips = list({a[4][0] for a in addrs})
                    return {"subdomain": fqdn, "ips": ips}
                except socket.gaierror:
                    return None

        tasks = [_resolve(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks)

        for r in results:
            if r is not None:
                found.append(r)

        return {
            "domain": domain,
            "total_checked": len(wordlist),
            "found": found,
        }

    async def technology_detection(self, domain: str) -> Dict[str, Any]:
        """Detect web technologies by inspecting HTTP response headers.

        Args:
            domain: The target domain.

        Returns:
            A dict with ``headers``, ``server``, ``technologies``, etc.
        """
        url = f"https://{domain}"
        result: Dict[str, Any] = {"domain": domain, "technologies": []}

        try:
            async with httpx.AsyncClient(
                timeout=self._timeout,
                follow_redirects=True,
                verify=False,
            ) as client:
                resp = await client.get(url)

            hdrs = dict(resp.headers)
            result["status_code"] = resp.status_code
            result["headers"] = hdrs

            server = hdrs.get("server", "")
            result["server"] = server

            # Fingerprint from headers
            tech_map = {
                "x-powered-by": lambda v: v,
                "x-aspnet-version": lambda _: "ASP.NET",
                "x-drupal-cache": lambda _: "Drupal",
                "x-generator": lambda v: v,
                "x-shopify-stage": lambda _: "Shopify",
            }

            for header, extractor in tech_map.items():
                val = hdrs.get(header)
                if val:
                    result["technologies"].append(extractor(val))

            if "cloudflare" in server.lower():
                result["technologies"].append("Cloudflare")
            if "nginx" in server.lower():
                result["technologies"].append("Nginx")
            if "apache" in server.lower():
                result["technologies"].append("Apache")

            # Check for common meta-data in body
            body = resp.text[:5000].lower()
            if "wp-content" in body or "wordpress" in body:
                result["technologies"].append("WordPress")
            if "react" in body or "reactdom" in body:
                result["technologies"].append("React")
            if "next.js" in body or "__next" in body:
                result["technologies"].append("Next.js")
            if "vue" in body:
                result["technologies"].append("Vue.js")
            if "bootstrap" in body:
                result["technologies"].append("Bootstrap")
            if "jquery" in body:
                result["technologies"].append("jQuery")

        except Exception as exc:
            result["error"] = str(exc)

        return result

    async def ssl_info(self, domain: str, port: int = 443) -> Dict[str, Any]:
        """Retrieve SSL/TLS certificate details.

        Args:
            domain: The target domain.
            port: TLS port (default 443).

        Returns:
            A dict with issuer, subject, validity dates, SANs, and protocol version.
        """
        result: Dict[str, Any] = {"domain": domain}

        try:
            loop = asyncio.get_event_loop()
            cert_info = await loop.run_in_executor(
                None, self._get_cert, domain, port
            )
            result.update(cert_info)
        except Exception as exc:
            result["error"] = str(exc)

        return result

    @staticmethod
    def _get_cert(domain: str, port: int) -> Dict[str, Any]:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info: Dict[str, Any] = {
                    "subject": dict(x[0] for x in cert.get("subject", ())),
                    "issuer": dict(x[0] for x in cert.get("issuer", ())),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "version": cert.get("version"),
                    "protocol": ssock.version(),
                }
                # Subject Alternative Names
                san = cert.get("subjectAltName", ())
                info["san"] = [v for _, v in san]
                return info
