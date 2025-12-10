import json
import base64
import re
import urllib.parse
from dataclasses import dataclass
from typing import Dict, Optional, List, Union
import logging
from pathlib import Path
import requests


@dataclass
class ProxyProfile:
    original_uri: str
    protocol: str
    address: str
    port: int
    tag: Optional[str] = "proxy"
    display_tag: Optional[str] = "Untitled"
    id: Optional[str] = ""
    security: Optional[str] = "none"
    network: Optional[str] = "tcp"
    header_type: Optional[str] = "none"
    host: Optional[str] = ""
    path: Optional[str] = ""
    sni: Optional[str] = ""
    fp: Optional[str] = ""
    alpn: Optional[str] = ""
    pbk: Optional[str] = ""
    sid: Optional[str] = ""
    spx: Optional[str] = ""
    flow: Optional[str] = ""
    encryption: Optional[str] = "none"
    alter_id: int = 0
    scy: Optional[str] = "auto"
    password: Optional[str] = ""
    ss_method: Optional[str] = "chacha20-poly1305"
    mode: Optional[str] = ""
    wg_secret_key: Optional[str] = ""
    wg_address: Optional[str] = "172.16.0.2/32"
    wg_reserved: Optional[str] = ""
    wg_mtu: int = 1420
    hy2_password: Optional[str] = ""
    hy2_obfs: Optional[str] = ""
    hy2_obfs_password: Optional[str] = ""
    mux_enabled: bool = False
    mux_concurrency: int = 8
    fragment_enabled: bool = False
    fragment_packets: Optional[str] = ""
    fragment_length: Optional[str] = ""
    fragment_interval: Optional[str] = ""


def _parse_query_params(query: str) -> Dict[str, str]:
    params = {}
    if not query:
        return params
    parsed_qs = urllib.parse.parse_qs(query, keep_blank_values=True)
    for key, values in parsed_qs.items():
        params[key] = values[-1] if values else ""
    return params


def parse_uri(config_uri: str) -> Optional[ProxyProfile]:
    try:
        uri = config_uri.strip()
        if not uri:
            return None
        protocol = uri.split("://")[0]
        if protocol not in [
            "vless",
            "mvless",
            "vmess",
            "trojan",
            "ss",
            "socks",
            "wireguard",
            "hysteria",
            "hysteria2",
            "hy2",
        ]:
            return None
        if protocol != "vmess":
            try:
                uri = urllib.parse.unquote(uri)
            except Exception:
                pass
            parsed_url = urllib.parse.urlparse(uri, scheme=protocol)
            decoded_display_tag = (
                urllib.parse.unquote(parsed_url.fragment)
                if parsed_url.fragment
                else "Untitled"
            )
            internal_safe_tag = (
                re.sub(r"[^a-zA-Z0-9_.-]", "_", decoded_display_tag) or "proxy"
            )
            netloc = parsed_url.netloc
            if "@" in netloc:
                netloc = netloc.split("@", 1)[1]
            ipv6_match = re.match(r"\[([a-fA-F0-9:]+)\]:(\d+)", netloc)
            if ipv6_match:
                address = ipv6_match.group(1)
                port = int(ipv6_match.group(2))
            else:

                try:
                    host_port_pair = netloc.rsplit(":", 1)
                    address = host_port_pair[0]
                    port = int(host_port_pair[1])
                except (ValueError, IndexError):

                    address = netloc
                    port = parsed_url.port or 0

            if address.startswith("[") and address.endswith("]"):
                address = address[1:-1]
            common = {
                "original_uri": config_uri,
                "protocol": protocol,
                "tag": internal_safe_tag,
                "display_tag": decoded_display_tag,
                "address": address,
                "port": port,
            }
        else:
            raw_tag_from_uri = uri.split("#", 1)[1] if "#" in uri else "Untitled"
            decoded_display_tag = urllib.parse.unquote(raw_tag_from_uri)
            internal_safe_tag = (
                re.sub(r"[^a-zA-Z0-9_.-]", "_", decoded_display_tag) or "proxy"
            )
            common = {
                "protocol": "vmess",
                "tag": internal_safe_tag,
                "display_tag": decoded_display_tag,
            }
            parsed_url = None
        parser_map = {
            "vless": _parse_vless,
            "mvless": _parse_vless,
            "vmess": _parse_vmess,
            "trojan": _parse_trojan,
            "ss": _parse_shadowsocks,
            "socks": _parse_socks,
            "wireguard": _parse_wireguard,
            "hysteria": _parse_hysteria,
            "hysteria2": _parse_hysteria,
            "hy2": _parse_hysteria,
        }
        parser = parser_map.get(protocol)
        if not parser:
            return None
        params = parser(uri, common, parsed_url)
        if not params:
            return None
        if not params.address or not params.port or params.port <= 0:
            return None
        if protocol == "mvless":
            _parse_mvless_extensions(params, uri)
        return params
    except Exception:
        return None


def _parse_vless(
    uri: str, common: dict, parsed_url: Optional[urllib.parse.ParseResult]
) -> Optional[ProxyProfile]:
    if not parsed_url:
        return None
    params = _parse_query_params(parsed_url.query)

    security = params.get("security", "none")
    pbk = params.get("pbk", "")
    sid = params.get("sid", "")
    spx = params.get("spx", "")
    if security == "reality" and not pbk:
        logging.warning(
            f"REALITY config '{common['display_tag']}' is missing public key (pbk). Skipping."
        )
        return None

    network_type = params.get("type", "tcp")
    path = params.get("path", "")
    host = params.get("host", "")
    sni = params.get("sni", host)
    if network_type == "grpc" and not path:
        path = params.get("serviceName", sni or host)
        if not path:
            return None
    return ProxyProfile(
        **common,
        id=parsed_url.username or "",
        security=security,
        pbk=pbk,
        sid=sid,
        spx=spx,
        network=network_type,
        header_type=params.get("headerType", "none"),
        host=host,
        path=path,
        sni=sni,
        fp=params.get("fp", ""),
        alpn=params.get("alpn", ""),
        flow=params.get("flow", ""),
        encryption=params.get("encryption", "none"),
    )


def _parse_trojan(
    uri: str, common: dict, parsed_url: Optional[urllib.parse.ParseResult]
) -> Optional[ProxyProfile]:
    if not parsed_url:
        return None
    params = _parse_query_params(parsed_url.query)

    security = params.get("security", "tls")
    pbk = params.get("pbk", "")
    sid = params.get("sid", "")
    spx = params.get("spx", "")
    if security == "reality" and not pbk:
        logging.warning(
            f"REALITY config '{common['display_tag']}' is missing public key (pbk). Skipping."
        )
        return None

    network_type = params.get("type", "tcp")
    path = params.get("path", "/")
    host = params.get("host", "")
    sni = params.get("sni", common.get("address", ""))
    if network_type == "grpc" and (not path or path == "/"):
        path = params.get("serviceName", sni or host)
        if not path:
            return None
    return ProxyProfile(
        **common,
        password=parsed_url.username or "",
        sni=sni,
        network=network_type,
        security=security,
        pbk=pbk,
        sid=sid,
        spx=spx,
        fp=params.get("fp", ""),
        header_type=params.get("headerType", "none"),
        host=host,
        path=path,
    )


def _parse_mvless_extensions(params: ProxyProfile, uri: str):
    try:
        query_params = _parse_query_params(urllib.parse.urlparse(uri).query)
        if query_params.get("mux", "").upper() == "ON":
            params.mux_enabled = True
            params.mux_concurrency = int(query_params.get("muxConcurrency", 8))
        if all(k in query_params for k in ["packets", "length", "interval"]):
            params.fragment_enabled = True
            params.fragment_packets = query_params["packets"]
            params.fragment_length = query_params["length"]
            params.fragment_interval = query_params["interval"]
    except Exception:
        pass


def _parse_vmess(
    uri: str, common: dict, parsed_url: Optional[urllib.parse.ParseResult]
) -> Optional[ProxyProfile]:
    try:
        encoded_part = uri.replace("vmess://", "").split("#")[0]
        decoded = json.loads(base64.b64decode(encoded_part + "==").decode("utf-8"))
        print(
            f"{decoded.get("pbk", "")} {decoded.get("sid", "")} {decoded.get("spx", "")}"
        )
        display_tag = decoded.get("ps", common["display_tag"])
        common["display_tag"] = display_tag
        common["tag"] = re.sub(r"[^a-zA-Z0-9_.-]", "_", display_tag) or "proxy"
        network_type = decoded.get("net", "tcp")
        path = decoded.get("path", "")
        host = decoded.get("host", "")
        sni = decoded.get("sni", host)
        if network_type == "grpc" and not path:
            path = decoded.get("serviceName", sni or host)
            if not path:
                return None
        return ProxyProfile(
            **common,
            address=decoded.get("add", ""),
            port=int(decoded.get("port", 0)),
            id=decoded.get("id", ""),
            alter_id=int(decoded.get("aid", 0)),
            scy=decoded.get("scy", "auto"),
            network=network_type,
            header_type=decoded.get("type", "none"),
            host=host,
            path=path,
            security="tls" if decoded.get("tls") else "none",
            sni=sni,
        )
    except Exception:
        return None


def _parse_shadowsocks(
    uri: str, common: dict, parsed_url: Optional[urllib.parse.ParseResult]
) -> Optional[ProxyProfile]:
    if not parsed_url:
        return None
    auth_part = parsed_url.username or ""
    if ":" not in auth_part and parsed_url.password is None:
        try:
            decoded_auth = base64.b64decode(
                str(parsed_url.netloc.split("@")[0]) + "=="
            ).decode("utf-8")
            if ":" in decoded_auth:
                method, password = decoded_auth.split(":", 1)
                return ProxyProfile(**common, ss_method=method, password=password)
        except Exception:
            pass
    if ":" in auth_part:
        method, password = auth_part.split(":", 1)
        return ProxyProfile(**common, ss_method=method, password=password)
    else:
        params = _parse_query_params(parsed_url.query)
        method = params.get("method", "chacha20-poly1305")
        return ProxyProfile(**common, ss_method=method, password=auth_part)


def _parse_socks(
    uri: str, common: dict, parsed_url: Optional[urllib.parse.ParseResult]
) -> Optional[ProxyProfile]:
    if not parsed_url:
        return None
    return ProxyProfile(**common, id=parsed_url.username, password=parsed_url.password)


def _parse_wireguard(
    uri: str, common: dict, parsed_url: Optional[urllib.parse.ParseResult]
) -> Optional[ProxyProfile]:
    if not parsed_url:
        return None
    params = _parse_query_params(parsed_url.query)
    wg_address_raw = params.get("address", "172.16.0.2/32")
    wg_address_clean = [addr.strip() for addr in wg_address_raw.split(",")]
    return ProxyProfile(
        **common,
        wg_secret_key=parsed_url.username or "",
        wg_address=",".join(wg_address_clean),
        pbk=params.get("publicKey", ""),
        wg_reserved=params.get("reserved", ""),
        wg_mtu=int(params.get("mtu", 1420)),
    )


def _parse_hysteria(
    uri: str, common: dict, parsed_url: Optional[urllib.parse.ParseResult]
) -> Optional[ProxyProfile]:
    if not parsed_url:
        return None
    params = _parse_query_params(parsed_url.query)
    return ProxyProfile(
        **common,
        hy2_password=parsed_url.username or "",
        security="tls",
        sni=params.get("sni", common.get("address", "")),
        alpn=params.get("alpn"),
        hy2_obfs=params.get("obfs"),
        hy2_obfs_password=params.get("obfs-password"),
    )


def fetch_from_subscription(
    url: str, timeout: int = 10, max_configs: Optional[int] = None
) -> List[str]:
    try:
        response = requests.get(url, timeout=timeout)
        response.raise_for_status()
        content = response.content
        try:
            decoded_content = base64.b64decode(content).decode("utf-8")
        except:
            decoded_content = content.decode("utf-8")
        uris = [uri.strip() for uri in decoded_content.splitlines() if uri.strip()]
        if max_configs and max_configs > 0:
            uris = uris[:max_configs]
        return uris
    except Exception:
        return []


def load_configs(
    source: Union[str, List[str], Path],
    is_subscription: bool = False,
    max_configs: Optional[int] = None,
) -> List[ProxyProfile]:
    raw_uris: List[str] = []
    if isinstance(source, str) and source.startswith(("http", "https")):
        raw_uris = (
            fetch_from_subscription(source, max_configs=max_configs)
            if is_subscription
            else [source]
        )
    elif isinstance(source, list):
        raw_uris = source
    elif isinstance(source, Path) and source.is_file():
        content = source.read_text("utf-8").strip()
        if is_subscription or content.startswith(("http", "https")):
            raw_uris = fetch_from_subscription(content, max_configs=max_configs)
        else:
            raw_uris = [line.strip() for line in content.splitlines() if line.strip()]
    if (
        isinstance(source, (Path, list))
        and not is_subscription
        and max_configs
        and max_configs > 0
    ):
        raw_uris = raw_uris[:max_configs]
    return [p for p in (parse_uri(uri) for uri in raw_uris) if p]


def deduplicate_configs(configs: List[ProxyProfile]) -> List[ProxyProfile]:
    unique_configs = {}
    for config in configs:
        key = tuple(
            str(getattr(config, p, ""))
            for p in [
                "protocol",
                "address",
                "port",
                "id",
                "password",
                "wg_secret_key",
                "hy2_password",
                "path",
                "sni",
                "host",
            ]
        )
        if key not in unique_configs:
            unique_configs[key] = config
    return list(unique_configs.values())
