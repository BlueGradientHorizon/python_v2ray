import html
import json
import base64
import re
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, Optional, List, Tuple, Union
from pathlib import Path
import requests

from python_v2ray.models.hysteria_config import (
    HysteriaConfig,
    Obfs,
    ObfsSalamander,
    ObfsType,
    Tls,
)
from python_v2ray.models.xray_core_config import (
    AuthenticatorRequest,
    DnsHeaderConfig,
    DtlsHeaderConfig,
    GrpcConfig,
    HttpHeaderConfig,
    HttpUpgradeConfig,
    KcpConfig,
    OutboundDetourConfig,
    RealityConfig,
    ShadowsocksClientConfig,
    SocksClientConfig,
    SplitHttpConfig,
    SrtpHeaderConfig,
    StreamConfig,
    TcpConfig,
    TlsConfig,
    TrojanClientConfig,
    UtpHeaderConfig,
    VLessOutboundConfig,
    VMessOutboundConfig,
    WebSocketConfig,
    WechatVideoHeaderConfig,
    WireGuardConfig,
    WireGuardPeerConfig,
    WireguardHeaderConfig,
)


@dataclass
class ProxyProfile:
    original_uri: str
    protocol: str
    # address: str
    # port: int
    outbound_config: Any = None
    # adapter: BaseProxyAdapter
    # # tag: str = "proxy"
    # display_tag: str = "Untitled"
    # id_: str = ""
    # security: str = "none"  # "none" | "tls" | "reality"
    # network: str = "raw"  # "raw" | "xhttp" | "kcp" | "grpc" | "ws" | "httpupgrade"
    # header_type: str = (
    #     "none"  # "none" | "srtp" | "utp" | "wechat-video" | "dtls" | "wireguard" | " dns"
    # )
    # host: str = ""
    # path: str = ""
    # sni: str = ""
    # fp: str = (
    #     "chrome"  # "chrome" | "firefox" | "safari" | "ios" | "android" | "edge" | "360" | "qq" | "random" | "randomized" | "unsafe"
    # )

    # alpn: str = ""
    # pbk: str = ""
    # sid: str = ""
    # spx: str = ""
    # flow: str = ""
    # encryption: str = "none"
    # alter_id: int = 0
    # scy: str = "auto"
    # password: str = ""
    # ss_method: str = "chacha20-poly1305"
    # mode: str = ""
    # wg_secret_key: str = ""
    # wg_address: str = "172.16.0.2/32"
    # wg_reserved: str = ""
    # wg_mtu: int = 1420
    # hy2_password: str = ""
    # hy2_obfs: str = ""
    # hy2_obfs_password: str = ""
    # mux_enabled: bool = False
    # mux_concurrency: int = 8
    # fragment_enabled: bool = False
    # fragment_packets: str = ""
    # fragment_length: str = ""
    # fragment_interval: str = ""


def _parse_query_params(query: str) -> Dict[str, str]:
    params = {}
    if not query:
        return params
    parsed_qs = urllib.parse.parse_qs(query, keep_blank_values=True)
    for key, values in parsed_qs.items():
        params[key] = values[-1] if values else ""
    return params


def _build_stream_settings(
    params: Dict[str, str], allow_insecure: bool = False, protocol: str = "vless"
) -> StreamConfig:
    stream_settings = StreamConfig()

    security_k = "security"
    type_k = "type"
    service_name_k = "serviceName"
    mode_k = "mode"

    if protocol == "vmess":
        security_k = "tls"
        type_k = "net"
        service_name_k = "path"
        mode_k = "type"

    security = params.get(security_k, "none")
    type_ = params.get(type_k, "raw")
    sni = params.get("sni")
    alpn = params.get("alpn", "")
    fp = params.get("fp")
    pbk = params.get("pbk")
    sid = params.get("sid")
    pqv = params.get("pqv")
    spx = params.get("spx")
    path = params.get("path")
    host = params.get("host")
    header_type = params.get("headerType", "none")
    service_name = params.get(service_name_k, sni or host)  # grpc
    authority = params.get("authority")
    seed = params.get("seed")
    mode = params.get(mode_k)  # grpc

    if security == "tls":
        stream_settings.security = security
        if fp not in [
            "chrome",
            "firefox",
            "safari",
            "ios",
            "android",
            "edge",
            "360",
            "qq",
            "random",
            "randomized",
            "unsafe",
        ]:
            fp = None
        stream_settings.tls_settings = TlsConfig(
            allow_insecure=allow_insecure,
            # certificates=,
            server_name=sni,
            alpn=[val.strip() for val in alpn.split(",")],
            # enable_session_resumption=,
            # disable_system_root=,
            # min_version=,
            # max_version=,
            # cipher_suites=,
            fingerprint=fp,
            # reject_unknown_sni=,
            # pinned_peer_certificate_chain_sha256=,
            # pinned_peer_certificate_public_key_sha256=
            # curve_preferences=,
            # master_key_log=,
            # verify_peer_cert_in_names=,
            # ech_server_keys=,
            ech_config_list=params.get("ech"),  # .replace(" ", "+", count=1),
            # ech_force_query=,
            # ech_sockopt=,
        )
    elif security == "reality":
        stream_settings.security = security
        stream_settings.reality_settings = RealityConfig(
            # master_key_log=,
            # show=,
            # target=,
            # dest=,
            # type=,
            # xver=,
            # server_names=,
            # private_key=,
            # min_client_ver=,
            # max_client_ver=,
            # max_time_diff=,
            # short_ids=,
            # mldsa65_seed=,
            # limit_fallback_upload=,
            # limit_fallback_download=,
            fingerprint=fp,
            server_name=sni,
            password=pbk,
            # public_key=pbk,
            short_id=sid,
            mldsa65_verify=pqv,
            spider_x=spx,
        )

    # h2, h3, http (REMOVED) > xhttp stream-one h2&h3
    # quic (REMOVED) > xhttp stream-one h3

    if type_ in ["raw", "tcp"]:
        stream_settings.network = "tcp"  # = Network.RAW
        stream_settings.raw_settings = TcpConfig(
            header=(
                HttpHeaderConfig(
                    request=AuthenticatorRequest(
                        version="1.1",
                        method="GET",
                        path=[path],
                        # headers=,
                    )
                )
                if path
                else None
            ),
            # accept_proxy_protocol=
        )
    elif type_ in ["ws", "websocket"]:
        stream_settings.network = "ws"  # = Network.WS
        stream_settings.ws_settings = WebSocketConfig(
            host=host,
            path=path or "/",
            # headers=,
            # accept_proxy_protocol=,
            # heartbeat_period=
        )
    elif type_ in ["kcp", "mkcp"]:
        stream_settings.network = "kcp"  # = Network.KCP
        h = None
        if header_type is not None:
            match header_type:
                case "srtp":
                    h = SrtpHeaderConfig()
                case "utp":
                    h = UtpHeaderConfig()
                case "wechat-video":
                    h = WechatVideoHeaderConfig()
                case "dtls":
                    h = DtlsHeaderConfig()
                case "wireguard":
                    h = WireguardHeaderConfig()
                case "dns":
                    h = DnsHeaderConfig()

        stream_settings.kcp_settings = KcpConfig(
            # mtu=,
            # tti=,
            # uplink_capacity=,
            # downlink_capacity=,
            # congestion=,
            # read_buffer_size=,
            # write_buffer_size=,
            header=h,
            seed=seed or path,
        )
    elif type_ == "grpc":
        stream_settings.network = "grpc"  # = Network.GRPC
        stream_settings.grpc_settings = GrpcConfig(
            authority=authority,
            service_name=service_name,
            multi_mode=mode == "multi",
            # idle_timeout=,
            # health_check_timeout=,
            # permit_without_stream=,
            # initial_windows_size=,
            # user_agent=
        )
    elif type_ in ["xhttp", "splithttp"]:
        stream_settings.network = "xhttp"  # = Network.XHTTP
        stream_settings.xhttp_settings = SplitHttpConfig(
            host=host or sni,
            path=path,
            # mode=,
            # headers=,
            # x_padding_bytes=,
            # no_grpc_header=,
            # no_sse_header=,
            # sc_max_each_post_bytes=,
            # sc_min_posts_interval_ms=,
            # sc_max_buffered_posts=,
            # sc_stream_up_server_secs=,
            # xmux=,
            # download_settings=,
            # extra=
        )
    elif type_ == "httpupgrade":
        stream_settings.network = "httpupgrade"
        stream_settings.httpupgrade_settings = HttpUpgradeConfig(
            host=host or sni,
            path=path,
            # headers=,
            # accept_proxy_protocol=,
        )
    return stream_settings


def _fix_trojan_uri(uri: str) -> Optional[urllib.parse.ParseResult]:
    if uri.count("@") > 1:
        return None

    a1 = uri.rsplit("@", 1)
    a2 = a1[0].split("://", 1)
    a3 = a1[1].split("?", 1)

    temp_uri = f"{a2[0]}://placeholder@{a1[1]}"
    r = urllib.parse.urlparse(temp_uri)
    r = r._replace(netloc=f"{a2[1]}@{a3[0].replace("/", "")}")
    return r


def _parse_config_uri(uri: str, scheme: str) -> Optional[urllib.parse.ParseResult]:
    try:
        uri = urllib.parse.unquote(uri)
        uri = html.unescape(uri)
    except Exception:
        pass

    if scheme == "trojan":
        try:
            return _fix_trojan_uri(uri)
        except Exception:
            return None

    try:
        return urllib.parse.urlparse(uri, scheme=scheme)
    except ValueError:
        return None


def _parse_netloc_for_endpoint(
    parsed_url: urllib.parse.ParseResult,
) -> Optional[Tuple[str, int]]:
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
            try:
                port = parsed_url.port or 0
            except ValueError:
                # Port could not be cast to integer value as 'Z'
                return None

    if address.startswith("[") and address.endswith("]"):
        address = address[1:-1]

    return (address, port)


def _extract_common_uri_data(
    uri: str, scheme: str
) -> Optional[Tuple[urllib.parse.ParseResult, str, int]]:
    if (parsed_url := _parse_config_uri(uri, scheme)) is None:
        return None

    if (addr_port_t := _parse_netloc_for_endpoint(parsed_url)) is None:
        return None

    address, port = addr_port_t

    return parsed_url, address, port


def parse_profile(config_uri: str) -> Optional[ProxyProfile]:
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

    parser_map = {
        "vless": _parse_vless,
        "mvless": _parse_vless,
        "vmess": _parse_vmess,
        "trojan": _parse_trojan,
        "ss": _parse_shadowsocks,
        "socks": _parse_socks,
        "wireguard": _parse_wireguard,
        # "hysteria": _parse_hysteria,
        # "hysteria2": _parse_hysteria,
        # "hy2": _parse_hysteria,
    }
    parser = parser_map.get(protocol)

    if parser is None:
        return None

    # outbound = parser(uri, common)
    outbound = parser(protocol, uri)

    if outbound is None:
        return None

    # if (
    #     not outbound.settings
    #     or not outbound.settings.address
    #     or not outbound.settings.port
    #     or outbound.settings.port <= 0
    # ):
    #     return None

    # if protocol == "mvless":
    #     _parse_mvless_extensions(params, uri)
    # return params

    # if isinstance(outbound, HysteriaConfig):
    #     adapter = HysteriaAdapter(outbound)
    # else:
    #     # Assuming it is OutboundDetourConfig for Xray
    #     adapter = XrayAdapter(outbound)

    p = ProxyProfile(
        original_uri=config_uri,
        protocol=protocol,
        # address=outbound.settings.address,
        # port=outbound.settings.port,
        # adapter=adapter,
        outbound_config=outbound,
    )
    return p


def _parse_vless(
    protocol: str,
    uri: str,
) -> Optional[OutboundDetourConfig]:
    if (common := _extract_common_uri_data(uri, protocol)) is None:
        return None

    parsed_url, address, port = common

    params = _parse_query_params(parsed_url.query)
    stream_settings = _build_stream_settings(params)

    level = 0
    id_ = parsed_url.username
    flow = params.get("flow")
    encryption = params.get(
        "encryption", "none"
    )  # TODO error `please add/set "encryption":"none" for every user`

    c = OutboundDetourConfig(
        protocol="vless",
        # send_through=,
        # tag=,
        settings=VLessOutboundConfig(
            address=address,
            port=port,
            level=level,
            # email=,
            id_=id_,
            flow=flow,
            # seed=params.get("seed"), # also commented out in xray source code
            encryption=encryption,
            # testpre=,
            # testseed=
        ),
        stream_settings=stream_settings,
        # proxy_settings=,
        # mux=,
        # target_strategy=
    )
    return c


def _parse_trojan(
    protocol: str,
    uri: str,
) -> Optional[OutboundDetourConfig]:
    if (common := _extract_common_uri_data(uri, protocol)) is None:
        return None

    parsed_url, address, port = common

    def get_fixed_password():
        try:
            return uri.rsplit("@", 1)[0].split("://", 1)[1]
        except Exception:
            return None

    params = _parse_query_params(parsed_url.query)
    stream_settings = _build_stream_settings(params)

    level = 0
    password = parsed_url.username or get_fixed_password()
    flow = params.get("flow")

    c = OutboundDetourConfig(
        protocol="trojan",
        # send_through=,
        # tag=,
        settings=TrojanClientConfig(
            address=address,
            port=port,
            level=level,
            # email=,
            password=password,
            flow=flow,
            # servers=,
        ),
        stream_settings=stream_settings,
        # proxy_settings=,
        # mux=,
        # target_strategy=
    )
    return c


# def _parse_mvless_extensions(params: ProxyProfile, uri: str):
#     try:
#         query_params = _parse_query_params(urllib.parse.urlparse(uri).query)
#         if query_params.get("mux", "").upper() == "ON":
#             params.mux_enabled = True
#             params.mux_concurrency = int(query_params.get("muxConcurrency", 8))
#         if all(k in query_params for k in ["packets", "length", "interval"]):
#             params.fragment_enabled = True
#             params.fragment_packets = query_params["packets"]
#             params.fragment_length = query_params["length"]
#             params.fragment_interval = query_params["interval"]
#     except Exception:
#         pass


def _parse_vmess(
    protocol: str,
    uri: str,
) -> Optional[OutboundDetourConfig]:
    try:
        encoded_part = uri.replace("vmess://", "").split("#")[0]
        decoded: Dict[str, str] = json.loads(
            base64.b64decode(encoded_part + "==").decode("utf-8")
        )
        stream_settings = _build_stream_settings(decoded, protocol="vmess")

        address = decoded.get("add")
        port = int(decoded.get("port", 0))
        level = 0
        email = decoded.get("ps")
        id_ = decoded.get("id")
        security = decoded.get("scy")

        c = OutboundDetourConfig(
            protocol="vmess",
            # send_through=,
            # tag=,
            settings=VMessOutboundConfig(
                address=address,
                port=port,
                level=level,
                email=email,
                id_=id_,
                security=security,
                # experiments=,
                # vnext=,
            ),
            stream_settings=stream_settings,
            # proxy_settings=,
            # mux=,
            # target_strategy=
        )
        return c
    except Exception:
        return None


def _parse_shadowsocks(
    protocol: str,
    uri: str,
) -> Optional[OutboundDetourConfig]:
    if (common := _extract_common_uri_data(uri, protocol)) is None:
        return None

    parsed_url, address, port = common

    params = _parse_query_params(parsed_url.query)
    stream_settings = _build_stream_settings(params)

    level = 0

    method = None
    password = None

    auth_part = parsed_url.username or ""
    if ":" not in auth_part and parsed_url.password is None:
        try:
            decoded_auth = base64.b64decode(
                str(parsed_url.netloc.split("@")[0]) + "=="
            ).decode("utf-8")
            if ":" in decoded_auth:
                method, password = decoded_auth.split(":", 1)
        except Exception:
            pass
    if not method and not password:
        if ":" in auth_part:
            method, password = auth_part.split(":", 1)
        else:
            method = params.get("method", "chacha20-poly1305")
            password = auth_part

    c = OutboundDetourConfig(
        protocol="shadowsocks",
        # send_through=,
        # tag=,
        settings=ShadowsocksClientConfig(
            address=address,
            port=port,
            level=level,
            # email=,
            method=method,
            password=password,
            # iv_check=,
            # uot=,
            # servers=
        ),
        stream_settings=stream_settings,
        # proxy_settings=,
        # mux=,
        # target_strategy=
    )
    return c


def _parse_socks(
    protocol: str,
    uri: str,
) -> Optional[OutboundDetourConfig]:
    if (common := _extract_common_uri_data(uri, protocol)) is None:
        return None

    parsed_url, address, port = common

    level = 0

    c = OutboundDetourConfig(
        protocol="socks",
        # send_through=,
        # tag=,
        settings=SocksClientConfig(
            address=address,
            port=port,
            level=level,
            # email=,
            user=parsed_url.username,
            pass_=parsed_url.password,
            # servers=
        ),
        # stream_settings=,
        # proxy_settings=,
        # mux=,
        # target_strategy=
    )
    return c


def _parse_wireguard(
    protocol: str,
    uri: str,
) -> Optional[OutboundDetourConfig]:
    if (common := _extract_common_uri_data(uri, protocol)) is None:
        return None

    parsed_url, address, port = common

    params = _parse_query_params(parsed_url.query)
    wg_address_raw = params.get("address", "172.16.0.2/32")
    wg_address_clean = [addr.strip() for addr in wg_address_raw.split(",")]
    mtu = params.get("mtu")
    reserved = params.get("reserved")
    publickey = params.get("publickey")
    peer_pk = params.get("peer_pk")
    presharedkey = params.get("presharedkey")
    workers = params.get("workers")

    c = OutboundDetourConfig(
        protocol="wireguard",
        # send_through=,
        # tag=,
        settings=WireGuardConfig(
            # is_client=,
            # no_kernel_tun=,
            secret_key=parsed_url.username or "",
            address=wg_address_clean,
            peers=[
                WireGuardPeerConfig(
                    public_key=peer_pk or publickey,
                    pre_shared_key=presharedkey,
                    endpoint=f"{address}:{port}",
                    # keep_alive=,
                    # allowed_ips=,
                )
            ],
            mtu=int(mtu) if mtu else None,
            workers=int(workers) if workers else None,
            reserved=[int(i) for i in reserved.split(",")] if reserved else None,
            # domain_strategy=,
        ),
        # stream_settings=,
        # proxy_settings=,
        # mux=,
        # target_strategy=
    )
    return c


def _parse_hysteria(
    # uri: str, common: dict, parsed_url: Optional[urllib.parse.ParseResult]
    protocol: str,
    uri: str,
) -> Optional[HysteriaConfig]:
    print(uri)
    if (common := _extract_common_uri_data(uri, protocol)) is None:
        return None

    parsed_url, address, port = common

    params = _parse_query_params(parsed_url.query)

    sni = params.get("sni")
    insecure = params.get("insecure")
    pin_sha256 = params.get("pinSHA256")
    obfs_type = params.get("obfs")
    obfs_salamander_password = params.get("obfs-password")

    # return ProxyProfile(
    #     **common,
    #     hy2_password=parsed_url.username or "",
    #     security="tls",
    #     sni=params.get("sni", common.get("address", "")),
    #     alpn=params.get("alpn"),
    #     hy2_obfs=params.get("obfs"),
    #     hy2_obfs_password=params.get("obfs-password"),
    # )
    return HysteriaConfig(
        server=f"{address}:{port}",
        auth=parsed_url.username or "",
        tls=Tls(
            sni=sni or address or "",
            insecure=insecure == "1",
            pin_sha256=pin_sha256,
            # ca=,
            # client_certificate=,
            # client_key=,
            # cert=,
            # key=,
            # sni_guard=,
            # client_ca=,
        ),
        # transport,
        obfs=(
            Obfs(
                type_=ObfsType(obfs_type),
                salamander=ObfsSalamander(password=obfs_salamander_password),
            )
            if obfs_type is not None
            else None
        ),
        # quic=,
        # bandwidth=,
        # fast_open=,
        # lazy=,
        # socks5=,
        # http=,
        # tcp_forwarding=,
        # udp_forwarding=,
        # tcp_tproxy=,
        # udp_tproxy=,
        # tcp_redirect=,
        # tun=,
        # listen=,
        # acme=,
        # ignore_client_bandwidth=,
        # speed_test=,
        # disable_udp=,
        # udp_idle_timeout=,
        # resolver=,
        # sniff=,
        # acl=,
        # outbounds=,
        # traffic_stats=,
        # masquerade=
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
    return [p for p in (parse_profile(uri) for uri in raw_uris) if p]


def deduplicate_configs(configs: List[ProxyProfile]) -> List[ProxyProfile]:
    unique_configs = {}
    for config in configs:
        key = config.original_uri
        if key not in unique_configs:
            unique_configs[key] = config
    return list(unique_configs.values())
