from dataclasses import dataclass
from typing import Optional, List, Dict, Union
from enum import Enum


class ObfsType(Enum):
    SALAMANDER = "salamander"


class TlsSniGuard(Enum):
    STRICT = "strict"
    DISABLE = "disable"
    DNS_SAN = "dns-san"


class TransportType(Enum):
    UDP = "udp"


class DirectMode(Enum):
    AUTO = "auto"
    IPV6_ONLY = "6"
    IPV4_ONLY = "4"
    IPV6_PREFERRED = "64"
    IPV4_PREFERRED = "46"


class OutboundType(Enum):
    DIRECT = "direct"
    SOCKS5 = "socks5"
    HTTP = "http"


class MasqueradeType(Enum):
    FILE = "file"
    PROXY = "proxy"
    STRING = "string"


class AuthType(Enum):
    PASSWORD = "password"
    USERPASS = "userpass"
    HTTP = "http"
    COMMAND = "command"


class ResolverType(Enum):
    UDP = "udp"
    TCP = "tcp"
    TLS = "tls"
    HTTPS = "https"


class AcmeType(Enum):
    HTTP = "http"
    TLS = "tls"
    DNS = "dns"


class AcmeCa(Enum):
    LETSENCRYPT = "letsencrypt"
    ZEROSSL = "zerossl"


class AcmeDnsProvider(Enum):
    CLOUDFLARE = "cloudflare"
    DUCKDNS = "duckdns"
    GANDI = "gandi"
    GODADDY = "godaddy"
    NAMEDOTCOM = "namedotcom"
    VULTR = "vultr"


class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARN = "warn"
    ERROR = "error"


class LogFormat(Enum):
    CONSOLE = "console"
    JSON = "json"


@dataclass
class ObfsSalamander:
    password: Optional[str] = None


@dataclass
class Obfs:
    type_: Optional[ObfsType] = None
    salamander: Optional[ObfsSalamander] = None


@dataclass
class Tls:
    sni: Optional[str] = None
    insecure: Optional[bool] = None
    pin_sha256: Optional[str] = None
    ca: Optional[str] = None
    client_certificate: Optional[str] = None
    client_key: Optional[str] = None
    cert: Optional[str] = None
    key: Optional[str] = None
    sni_guard: Optional[TlsSniGuard] = None
    client_ca: Optional[str] = None


@dataclass
class TransportUdp:
    hop_interval: Optional[str] = None


@dataclass
class Transport:
    type_: Optional[TransportType] = None
    udp: Optional[TransportUdp] = None


@dataclass
class QuicSockopts:
    bind_interface: Optional[str] = None
    fwmark: Optional[int] = None
    fd_control_unix_socket: Optional[str] = None


@dataclass
class Quic:
    init_stream_receive_window: Optional[int] = None
    max_stream_receive_window: Optional[int] = None
    init_conn_receive_window: Optional[int] = None
    max_conn_receive_window: Optional[int] = None
    max_idle_timeout: Optional[str] = None
    keep_alive_period: Optional[str] = None
    disable_path_mtu_discovery: Optional[bool] = None
    sockopts: Optional[QuicSockopts] = None
    max_incoming_streams: Optional[int] = None


@dataclass
class Bandwidth:
    up: Optional[str] = None
    down: Optional[str] = None


@dataclass
class Socks5Inbound:
    listen: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    disable_udp: Optional[bool] = None


@dataclass
class HttpInbound:
    listen: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    realm: Optional[str] = None


@dataclass
class TcpForwarding:
    listen: Optional[str] = None
    remote: Optional[str] = None


@dataclass
class UdpForwarding:
    listen: Optional[str] = None
    remote: Optional[str] = None
    timeout: Optional[str] = None


@dataclass
class TcpTProxy:
    listen: Optional[str] = None


@dataclass
class UdpTProxy:
    listen: Optional[str] = None
    timeout: Optional[str] = None


@dataclass
class TcpRedirect:
    listen: Optional[str] = None


@dataclass
class TunRoute:
    ipv4: Optional[List[str]] = None
    ipv6: Optional[List[str]] = None
    ipv4_exclude: Optional[List[str]] = None
    ipv6_exclude: Optional[List[str]] = None


@dataclass
class TunAddress:
    ipv4: Optional[str] = None
    ipv6: Optional[str] = None


@dataclass
class Tun:
    name: Optional[str] = None
    mtu: Optional[int] = None
    timeout: Optional[str] = None
    address: Optional[TunAddress] = None
    route: Optional[TunRoute] = None


@dataclass
class ServerAuthHttp:
    url: Optional[str] = None
    insecure: Optional[bool] = None


@dataclass
class ServerAuth:
    type_: Optional[AuthType] = None
    password: Optional[str] = None
    userpass: Optional[Dict[str, str]] = None
    http: Optional[ServerAuthHttp] = None
    command: Optional[str] = None


@dataclass
class ResolverTcp:
    addr: Optional[str] = None
    timeout: Optional[str] = None


@dataclass
class ResolverUdp:
    addr: Optional[str] = None
    timeout: Optional[str] = None


@dataclass
class ResolverTls:
    addr: Optional[str] = None
    timeout: Optional[str] = None
    sni: Optional[str] = None
    insecure: Optional[bool] = None


@dataclass
class ResolverHttps:
    addr: Optional[str] = None
    timeout: Optional[str] = None
    sni: Optional[str] = None
    insecure: Optional[bool] = None


@dataclass
class Resolver:
    type_: Optional[ResolverType] = None
    tcp: Optional[ResolverTcp] = None
    udp: Optional[ResolverUdp] = None
    tls: Optional[ResolverTls] = None
    https: Optional[ResolverHttps] = None


@dataclass
class Sniff:
    enable: Optional[bool] = None
    timeout: Optional[str] = None
    rewrite_domain: Optional[bool] = None
    tcp_ports: Optional[str] = None
    udp_ports: Optional[str] = None


@dataclass
class Acl:
    file: Optional[str] = None
    inline: Optional[List[str]] = None
    geoip: Optional[str] = None
    geosite: Optional[str] = None
    geo_update_interval: Optional[str] = None


@dataclass
class OutboundDirect:
    mode: Optional[DirectMode] = None
    bind_ipv4: Optional[str] = None
    bind_ipv6: Optional[str] = None
    bind_device: Optional[str] = None
    fast_open: Optional[bool] = None


@dataclass
class OutboundSocks5:
    addr: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass
class OutboundHttp:
    url: Optional[str] = None
    insecure: Optional[bool] = None


@dataclass
class Outbound:
    name: Optional[str] = None
    type_: Optional[OutboundType] = None
    direct: Optional[OutboundDirect] = None
    socks5: Optional[OutboundSocks5] = None
    http: Optional[OutboundHttp] = None


@dataclass
class TrafficStats:
    listen: Optional[str] = None
    secret: Optional[str] = None


@dataclass
class MasqueradeFile:
    dir_: Optional[str] = None


@dataclass
class MasqueradeProxy:
    url: Optional[str] = None
    rewrite_host: Optional[bool] = None
    insecure: Optional[bool] = None


@dataclass
class MasqueradeString:
    content: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    status_code: Optional[int] = None


@dataclass
class Masquerade:
    type_: Optional[MasqueradeType] = None
    file: Optional[MasqueradeFile] = None
    proxy: Optional[MasqueradeProxy] = None
    string: Optional[MasqueradeString] = None
    listen_http: Optional[str] = None
    listen_https: Optional[str] = None
    force_https: Optional[bool] = None


@dataclass
class AcmeHttp:
    alt_port: Optional[int] = None


@dataclass
class AcmeTls:
    alt_port: Optional[int] = None


@dataclass
class AcmeDns:
    name: Optional[AcmeDnsProvider] = None
    config: Optional[Dict[str, str]] = None


@dataclass
class Acme:
    domains: Optional[List[str]] = None
    email: Optional[str] = None
    ca: Optional[AcmeCa] = None
    listen_host: Optional[str] = None
    dir_: Optional[str] = None
    type_: Optional[AcmeType] = None
    http: Optional[AcmeHttp] = None
    tls: Optional[AcmeTls] = None
    dns: Optional[AcmeDns] = None


@dataclass
class HysteriaConfig:
    server: Optional[str] = None
    auth: Optional[Union[str, ServerAuth]] = None
    tls: Optional[Tls] = None
    transport: Optional[Transport] = None
    obfs: Optional[Obfs] = None
    quic: Optional[Quic] = None
    bandwidth: Optional[Bandwidth] = None
    fast_open: Optional[bool] = None
    lazy: Optional[bool] = None
    socks5: Optional[Socks5Inbound] = None
    http: Optional[HttpInbound] = None
    tcp_forwarding: Optional[List[TcpForwarding]] = None
    udp_forwarding: Optional[List[UdpForwarding]] = None
    tcp_tproxy: Optional[TcpTProxy] = None
    udp_tproxy: Optional[UdpTProxy] = None
    tcp_redirect: Optional[TcpRedirect] = None
    tun: Optional[Tun] = None
    listen: Optional[str] = None
    acme: Optional[Acme] = None
    ignore_client_bandwidth: Optional[bool] = None
    speed_test: Optional[bool] = None
    disable_udp: Optional[bool] = None
    udp_idle_timeout: Optional[str] = None
    resolver: Optional[Resolver] = None
    sniff: Optional[Sniff] = None
    acl: Optional[Acl] = None
    outbounds: Optional[List[Outbound]] = None
    traffic_stats: Optional[TrafficStats] = None
    masquerade: Optional[Masquerade] = None
