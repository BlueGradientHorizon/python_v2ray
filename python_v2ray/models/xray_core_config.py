from dataclasses import dataclass
from typing import List, Optional, Dict, Union
from enum import Enum

# --- Common Enums ---


class Network(Enum):
    TCP = "tcp"
    UDP = "udp"
    UNIX = "unix"


class DomainStrategy(Enum):
    AS_IS = "AsIs"
    USE_IP = "UseIP"
    USE_IPV4 = "UseIPv4"
    USE_IPV6 = "UseIPv6"
    USE_IPV4V6 = "UseIPv4v6"
    USE_IPV6V4 = "UseIPv6v4"
    FORCE_IP = "ForceIP"
    FORCE_IPV4 = "ForceIPv4"
    FORCE_IPV6 = "ForceIPv6"
    FORCE_IPV4V6 = "ForceIPv4v6"
    FORCE_IPV6V4 = "ForceIPv6v4"


class Security(Enum):
    NONE = "none"
    TLS = "tls"
    REALITY = "reality"


class LogLevel(Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    NONE = "none"


# --- Common Types ---


@dataclass
class Int32Range:
    from_: Optional[int] = None
    to: Optional[int] = None


# --- Inbound/Outbound Protocol Configurations ---


# Dokodemo (Door/Tunnel)
@dataclass
class DokodemoConfig:
    address: Optional[str] = None
    port: Optional[int] = None
    port_map: Optional[Dict[str, str]] = None
    network: Optional[Union[str, List[Network]]] = None
    follow_redirect: Optional[bool] = None
    user_level: Optional[int] = None


# HTTP
@dataclass
class HttpAccount:
    user: Optional[str] = None
    pass_: Optional[str] = None


@dataclass
class HttpServerConfig:
    accounts: Optional[List[HttpAccount]] = None
    allow_transparent: Optional[bool] = None
    user_level: Optional[int] = None


@dataclass
class HttpRemoteConfig:
    address: Optional[str] = None
    port: Optional[int] = None
    users: Optional[List[HttpAccount]] = None


@dataclass
class HttpClientConfig:
    address: Optional[str] = None
    port: Optional[int] = None
    level: Optional[int] = None
    email: Optional[str] = None
    user: Optional[str] = None
    pass_: Optional[str] = None
    servers: Optional[List[HttpRemoteConfig]] = None
    headers: Optional[Dict[str, str]] = None


# Shadowsocks
@dataclass
class ShadowsocksUserConfig:
    method: Optional[str] = None
    password: Optional[str] = None
    level: Optional[int] = None
    email: Optional[str] = None
    address: Optional[str] = None
    port: Optional[int] = None


@dataclass
class ShadowsocksServerConfig:
    method: Optional[str] = None
    password: Optional[str] = None
    level: Optional[int] = None
    email: Optional[str] = None
    clients: Optional[List[ShadowsocksUserConfig]] = None
    network: Optional[Union[str, List[Network]]] = None
    iv_check: Optional[bool] = None


@dataclass
class ShadowsocksServerTarget:
    address: Optional[str] = None
    port: Optional[int] = None
    level: Optional[int] = None
    email: Optional[str] = None
    method: Optional[str] = None
    password: Optional[str] = None
    iv_check: Optional[bool] = None
    uot: Optional[bool] = None
    uot_version: Optional[int] = None


@dataclass
class ShadowsocksClientConfig:
    address: Optional[str] = None
    port: Optional[int] = None
    level: Optional[int] = None
    email: Optional[str] = None
    method: Optional[str] = None
    password: Optional[str] = None
    iv_check: Optional[bool] = None
    uot: Optional[bool] = None
    uot_version: Optional[int] = None
    servers: Optional[List[ShadowsocksServerTarget]] = None


# Socks
@dataclass
class SocksAccount:
    user: Optional[str] = None
    pass_: Optional[str] = None


@dataclass
class SocksServerConfig:
    auth: Optional[str] = None
    accounts: Optional[List[SocksAccount]] = None
    udp: Optional[bool] = None
    ip: Optional[str] = None
    user_level: Optional[int] = None


@dataclass
class SocksRemoteConfig:
    address: Optional[str] = None
    port: Optional[int] = None
    users: Optional[List[SocksAccount]] = None


@dataclass
class SocksClientConfig:
    address: Optional[str] = None
    port: Optional[int] = None
    level: Optional[int] = None
    email: Optional[str] = None
    user: Optional[str] = None
    pass_: Optional[str] = None
    servers: Optional[List[SocksRemoteConfig]] = None


# Trojan
@dataclass
class TrojanUserConfig:
    password: Optional[str] = None
    level: Optional[int] = None
    email: Optional[str] = None
    flow: Optional[str] = None


@dataclass
class TrojanInboundFallback:
    name: Optional[str] = None
    alpn: Optional[str] = None
    path: Optional[str] = None
    type: Optional[str] = None
    dest: Optional[Union[str, int]] = None
    xver: Optional[int] = None


@dataclass
class TrojanServerConfig:
    clients: Optional[List[TrojanUserConfig]] = None
    fallbacks: Optional[List[TrojanInboundFallback]] = None


@dataclass
class TrojanServerTarget:
    address: Optional[str] = None
    port: Optional[int] = None
    level: Optional[int] = None
    email: Optional[str] = None
    password: Optional[str] = None
    flow: Optional[str] = None


@dataclass
class TrojanClientConfig:
    address: Optional[str] = None
    port: Optional[int] = None
    level: Optional[int] = None
    email: Optional[str] = None
    password: Optional[str] = None
    flow: Optional[str] = None
    servers: Optional[List[TrojanServerTarget]] = None


# VLESS
@dataclass
class VLessUserAccount:
    id_: Optional[str] = None
    flow: Optional[str] = None
    encryption: Optional[str] = None
    level: Optional[int] = None
    email: Optional[str] = None


@dataclass
class VLessInboundFallback:
    name: Optional[str] = None
    alpn: Optional[str] = None
    path: Optional[str] = None
    type: Optional[str] = None
    dest: Optional[Union[str, int]] = None
    xver: Optional[int] = None


@dataclass
class VLessInboundConfig:
    clients: Optional[List[VLessUserAccount]] = None
    decryption: Optional[str] = None
    fallbacks: Optional[List[VLessInboundFallback]] = None
    flow: Optional[str] = None
    testseed: Optional[List[int]] = None


@dataclass
class VLessOutboundVnext:
    address: Optional[str] = None
    port: Optional[int] = None
    users: Optional[List[VLessUserAccount]] = None


@dataclass
class VLessOutboundConfig:
    address: Optional[str] = None
    port: Optional[int] = None
    level: Optional[int] = None
    email: Optional[str] = None
    id_: Optional[str] = None
    flow: Optional[str] = None
    seed: Optional[str] = None
    encryption: Optional[str] = None
    testpre: Optional[int] = None
    testseed: Optional[List[int]] = None
    vnext: Optional[List[VLessOutboundVnext]] = None


# VMess
@dataclass
class VMessAccount:
    id_: Optional[str] = None
    security: Optional[str] = None  # TODO enum
    experiments: Optional[str] = None


@dataclass
class VMessDefaultConfig:
    level: Optional[int] = None


@dataclass
class VMessInboundConfig:
    clients: Optional[List[VMessAccount]] = None
    default: Optional[VMessDefaultConfig] = None


@dataclass
class VMessOutboundTarget:
    address: Optional[str] = None
    port: Optional[int] = None
    users: Optional[List[VMessAccount]] = None


@dataclass
class VMessOutboundConfig:
    address: Optional[str] = None
    port: Optional[int] = None
    level: Optional[int] = None
    email: Optional[str] = None
    id_: Optional[str] = None
    security: Optional[str] = None
    experiments: Optional[str] = None
    vnext: Optional[List[VMessOutboundTarget]] = None


# WireGuard
@dataclass
class WireGuardPeerConfig:
    public_key: Optional[str] = None
    pre_shared_key: Optional[str] = None
    endpoint: Optional[str] = None
    keep_alive: Optional[int] = None
    allowed_ips: Optional[List[str]] = None


@dataclass
class WireGuardConfig:
    is_client: Optional[bool] = None
    no_kernel_tun: Optional[bool] = None
    secret_key: Optional[str] = None
    address: Optional[List[str]] = None
    peers: Optional[List[WireGuardPeerConfig]] = None
    mtu: Optional[int] = None
    workers: Optional[int] = None
    reserved: Optional[List[int]] = None  # byte array in Go
    domain_strategy: Optional[str] = None


# Blackhole
@dataclass
class BlackholeResponse:
    type: Optional[str] = None
    "Values: none, http"


@dataclass
class BlackholeConfig:
    response: Optional[BlackholeResponse] = None


# Freedom (Direct)
@dataclass
class Fragment:
    packets: Optional[str] = None
    length: Optional[Int32Range] = None
    interval: Optional[Int32Range] = None
    max_split: Optional[Int32Range] = None


@dataclass
class Noise:
    type: Optional[str] = None
    packet: Optional[str] = None
    delay: Optional[Int32Range] = None
    apply_to: Optional[str] = None


@dataclass
class FreedomConfig:
    target_strategy: Optional[str] = None
    domain_strategy: Optional[str] = None
    redirect: Optional[str] = None
    user_level: Optional[int] = None
    fragment: Optional[Fragment] = None
    noises: Optional[List[Noise]] = None
    proxy_protocol: Optional[int] = None


# DNS Outbound
@dataclass
class DnsOutboundConfig:
    network: Optional[Network] = None
    address: Optional[str] = None
    port: Optional[int] = None
    user_level: Optional[int] = None
    non_ip_query: Optional[str] = None
    block_types: Optional[List[int]] = None


# Loopback
@dataclass
class LoopbackConfig:
    inbound_tag: Optional[str] = None


# --- Transport Configurations ---


# Transport Authenticators / Headers
@dataclass
class AuthenticatorRequest:
    version: Optional[str] = None
    method: Optional[str] = None
    path: Optional[List[str]] = None
    headers: Optional[Dict[str, List[str]]] = None


@dataclass
class AuthenticatorResponse:
    version: Optional[str] = None
    status: Optional[str] = None
    reason: Optional[str] = None
    headers: Optional[Dict[str, List[str]]] = None


@dataclass
class HttpHeaderConfig:
    type_: str = "http"
    request: Optional[AuthenticatorRequest] = None
    response: Optional[AuthenticatorResponse] = None


@dataclass
class SrtpHeaderConfig:
    type_: str = "srtp"
    version: Optional[int] = None
    padding: Optional[bool] = None
    extension: Optional[bool] = None
    csrc_count: Optional[int] = None
    marker: Optional[bool] = None
    payload_type: Optional[int] = None


@dataclass
class UtpHeaderConfig:
    type_: str = "utp"
    version: Optional[int] = None


@dataclass
class WechatVideoHeaderConfig:
    type_: str = "wechat-video"


@dataclass
class DtlsHeaderConfig:
    type_: str = "dtls"


@dataclass
class WireguardHeaderConfig:
    type_: str = "wireguard"


@dataclass
class DnsHeaderConfig:
    type_: str = "dns"
    domain: Optional[str] = None


# TCP
@dataclass
class TcpConfig:
    header: Optional[Union[HttpHeaderConfig, Dict]] = None
    "Dict often used to specify {'type': 'none'|'http'}"
    accept_proxy_protocol: Optional[bool] = None


KcpConfigHeaderType = (
    SrtpHeaderConfig
    | UtpHeaderConfig
    | WechatVideoHeaderConfig
    | DtlsHeaderConfig
    | WireguardHeaderConfig
    | DnsHeaderConfig
    | Dict
)


# mKCP
@dataclass
class KcpConfig:
    mtu: Optional[int] = None
    "Range: 576-1460"
    tti: Optional[int] = None
    "Range: 10-100"
    uplink_capacity: Optional[int] = None
    downlink_capacity: Optional[int] = None
    congestion: Optional[bool] = None
    read_buffer_size: Optional[int] = None
    write_buffer_size: Optional[int] = None
    header: Optional[KcpConfigHeaderType] = None
    "Dict used for type specification e.g., {'type': 'srtp'}"
    seed: Optional[str] = None


# WebSocket
@dataclass
class WebSocketConfig:
    host: Optional[str] = None
    path: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    accept_proxy_protocol: Optional[bool] = None
    heartbeat_period: Optional[int] = None


# HTTPUpgrade
@dataclass
class HttpUpgradeConfig:
    host: Optional[str] = None
    path: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    accept_proxy_protocol: Optional[bool] = None


# SplitHTTP
@dataclass
class XmuxConfig:
    max_concurrency: Optional[Int32Range] = None
    max_connections: Optional[Int32Range] = None
    c_max_reuse_times: Optional[Int32Range] = None
    h_max_request_times: Optional[Int32Range] = None
    h_max_reusable_secs: Optional[Int32Range] = None
    h_keep_alive_period: Optional[int] = None


@dataclass
class SplitHttpConfig:
    host: Optional[str] = None
    path: Optional[str] = None
    mode: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    x_padding_bytes: Optional[Int32Range] = None
    no_grpc_header: Optional[bool] = None
    no_sse_header: Optional[bool] = None
    sc_max_each_post_bytes: Optional[Int32Range] = None
    sc_min_posts_interval_ms: Optional[Int32Range] = None
    sc_max_buffered_posts: Optional[int] = None
    sc_stream_up_server_secs: Optional[Int32Range] = None
    xmux: Optional[XmuxConfig] = None
    download_settings: Optional["StreamConfig"] = None
    extra: Optional[Dict] = None


# gRPC
@dataclass
class GrpcConfig:
    authority: Optional[str] = None
    service_name: Optional[str] = None
    multi_mode: Optional[bool] = None
    idle_timeout: Optional[int] = None
    health_check_timeout: Optional[int] = None
    permit_without_stream: Optional[bool] = None
    initial_windows_size: Optional[int] = None
    user_agent: Optional[str] = None


# TLS
@dataclass
class TlsCertConfig:
    certificate_file: Optional[str] = None
    certificate: Optional[List[str]] = None
    key_file: Optional[str] = None
    key: Optional[List[str]] = None
    usage: Optional[str] = None
    ocsp_stapling: Optional[int] = None
    one_time_loading: Optional[bool] = None
    build_chain: Optional[bool] = None


@dataclass
class SocketConfig:
    mark: Optional[int] = None
    tcp_fast_open: Optional[Union[bool, int]] = None
    tproxy: Optional[str] = None
    accept_proxy_protocol: Optional[bool] = None
    domain_strategy: Optional[str] = None
    dialer_proxy: Optional[str] = None
    tcp_keep_alive_interval: Optional[int] = None
    tcp_keep_alive_idle: Optional[int] = None
    tcp_congestion: Optional[str] = None
    tcp_window_clamp: Optional[int] = None
    tcp_max_seg: Optional[int] = None
    penetrate: Optional[bool] = None
    tcp_user_timeout: Optional[int] = None
    v6only: Optional[bool] = None
    interface: Optional[str] = None
    tcp_mptcp: Optional[bool] = None
    custom_sockopt: Optional[List[Dict[str, str]]] = None
    address_port_strategy: Optional[str] = None
    happy_eyeballs: Optional[Dict[str, Union[bool, int]]] = None
    trusted_x_forwarded_for: Optional[List[str]] = None


@dataclass
class TlsConfig:
    allow_insecure: Optional[bool] = None
    certificates: Optional[List[TlsCertConfig]] = None
    server_name: Optional[str] = None
    alpn: Optional[List[str]] = None
    enable_session_resumption: Optional[bool] = None
    disable_system_root: Optional[bool] = None
    min_version: Optional[str] = None
    max_version: Optional[str] = None
    cipher_suites: Optional[str] = None
    fingerprint: Optional[str] = None # TODO enum
    reject_unknown_sni: Optional[bool] = None
    pinned_peer_certificate_chain_sha256: Optional[List[str]] = None
    pinned_peer_certificate_public_key_sha256: Optional[List[str]] = None
    curve_preferences: Optional[List[str]] = None
    master_key_log: Optional[str] = None
    verify_peer_cert_in_names: Optional[List[str]] = None
    ech_server_keys: Optional[str] = None
    ech_config_list: Optional[str] = None
    ech_force_query: Optional[str] = None
    ech_sockopt: Optional[SocketConfig] = None


# REALITY
@dataclass
class LimitFallback:
    after_bytes: Optional[int] = None
    bytes_per_sec: Optional[int] = None
    burst_bytes_per_sec: Optional[int] = None


@dataclass
class RealityConfig:
    master_key_log: Optional[str] = None
    show: Optional[bool] = None
    target: Optional[Union[str, int]] = None
    dest: Optional[Union[str, int]] = None
    type: Optional[str] = None
    xver: Optional[int] = None
    server_names: Optional[List[str]] = None
    private_key: Optional[str] = None
    min_client_ver: Optional[str] = None
    max_client_ver: Optional[str] = None
    max_time_diff: Optional[int] = None
    short_ids: Optional[List[str]] = None
    mldsa65_seed: Optional[str] = None
    limit_fallback_upload: Optional[LimitFallback] = None
    limit_fallback_download: Optional[LimitFallback] = None
    fingerprint: Optional[str] = None
    server_name: Optional[str] = None
    password: Optional[str] = None
    public_key: Optional[str] = None
    short_id: Optional[str] = None
    mldsa65_verify: Optional[str] = None
    spider_x: Optional[str] = None


# Stream Settings
@dataclass
class StreamConfig:
    address: Optional[str] = None
    port: Optional[int] = None
    network: Optional[str] = None
    security: Optional[str] = None
    tls_settings: Optional[TlsConfig] = None
    reality_settings: Optional[RealityConfig] = None
    raw_settings: Optional[TcpConfig] = None
    tcp_settings: Optional[TcpConfig] = None
    xhttp_settings: Optional[SplitHttpConfig] = None
    splithttp_settings: Optional[SplitHttpConfig] = None
    kcp_settings: Optional[KcpConfig] = None
    grpc_settings: Optional[GrpcConfig] = None
    ws_settings: Optional[WebSocketConfig] = None
    httpupgrade_settings: Optional[HttpUpgradeConfig] = None
    sockopt: Optional[SocketConfig] = None


# --- Top Level Inbound/Outbound Detours ---


@dataclass
class SniffingConfig:
    enabled: Optional[bool] = None
    dest_override: Optional[List[str]] = None
    domains_excluded: Optional[List[str]] = None
    metadata_only: Optional[bool] = None
    route_only: Optional[bool] = None


@dataclass
class MuxConfig:
    enabled: Optional[bool] = None
    concurrency: Optional[int] = None
    xudp_concurrency: Optional[int] = None
    xudp_proxy_udp443: Optional[str] = None


@dataclass
class ProxyConfig:
    tag: Optional[str] = None
    transport_layer: Optional[bool] = None


InboundDetourConfigSettings = (
    DokodemoConfig
    | HttpServerConfig
    | ShadowsocksServerConfig
    | SocksServerConfig
    | VLessInboundConfig
    | VMessInboundConfig
    | TrojanServerConfig
    | WireGuardConfig
)


@dataclass
class InboundDetourConfig:
    protocol: Optional[str] = None
    port: Optional[Union[int, str]] = None
    listen: Optional[str] = None
    settings: Optional[InboundDetourConfigSettings] = None
    tag: Optional[str] = None
    stream_settings: Optional[StreamConfig] = None
    sniffing: Optional[SniffingConfig] = None


OutboundDetourConfigSettings = (
    BlackholeConfig
    | FreedomConfig
    | HttpClientConfig
    | ShadowsocksClientConfig
    | SocksClientConfig
    | VLessOutboundConfig
    | VMessOutboundConfig
    | TrojanClientConfig
    | DnsOutboundConfig
    | WireGuardConfig
    | LoopbackConfig
)


@dataclass
class OutboundDetourConfig:
    protocol: Optional[str] = None
    send_through: Optional[str] = None
    tag: Optional[str] = None
    settings: Optional[OutboundDetourConfigSettings] = None
    stream_settings: Optional[StreamConfig] = None
    proxy_settings: Optional[ProxyConfig] = None
    mux: Optional[MuxConfig] = None
    target_strategy: Optional[str] = None


# --- Other Infrastructure ---


@dataclass
class LogConfig:
    access: Optional[str] = None
    error: Optional[str] = None
    loglevel: Optional[Union[str, LogLevel]] = None
    "Default: warning"
    dns_log: Optional[bool] = None
    mask_address: Optional[str] = None


@dataclass
class ApiConfig:
    tag: Optional[str] = None
    listen: Optional[str] = None
    services: Optional[List[str]] = None


@dataclass
class NameServerConfig:
    address: Optional[str] = None
    client_ip: Optional[str] = None
    port: Optional[int] = None
    skip_fallback: Optional[bool] = None
    domains: Optional[List[str]] = None
    expected_ips: Optional[List[str]] = None
    expect_ips: Optional[List[str]] = None
    query_strategy: Optional[str] = None
    tag: Optional[str] = None
    timeout_ms: Optional[int] = None
    disable_cache: Optional[bool] = None
    serve_stale: Optional[bool] = None
    serve_expired_ttl: Optional[int] = None
    final_query: Optional[bool] = None
    unexpected_ips: Optional[List[str]] = None


@dataclass
class HostsWrapper:
    hosts: Optional[Dict[str, Union[str, List[str]]]] = None


@dataclass
class DnsConfig:
    servers: Optional[List[Union[str, NameServerConfig]]] = None
    hosts: Optional[Dict[str, Union[str, List[str]]]] = None
    client_ip: Optional[str] = None
    tag: Optional[str] = None
    query_strategy: Optional[str] = None
    disable_cache: Optional[bool] = None
    serve_stale: Optional[bool] = None
    serve_expired_ttl: Optional[int] = None
    disable_fallback: Optional[bool] = None
    disable_fallback_if_match: Optional[bool] = None
    enable_parallel_query: Optional[bool] = None
    use_system_hosts: Optional[bool] = None


@dataclass
class StrategyConfig:
    type: Optional[str] = None
    settings: Optional[Dict] = None


@dataclass
class BalancingRule:
    tag: Optional[str] = None
    selector: Optional[List[str]] = None
    strategy: Optional[StrategyConfig] = None
    fallback_tag: Optional[str] = None


@dataclass
class RouterRule:
    rule_tag: Optional[str] = None
    outbound_tag: Optional[str] = None
    balancer_tag: Optional[str] = None
    domain: Optional[List[str]] = None
    domains: Optional[List[str]] = None
    ip: Optional[List[str]] = None
    port: Optional[Union[int, str]] = None
    network: Optional[Union[str, List[Network]]] = None
    source_ip: Optional[List[str]] = None
    source: Optional[List[str]] = None
    source_port: Optional[Union[int, str]] = None
    user: Optional[List[str]] = None
    vless_route: Optional[Union[int, str]] = None
    inbound_tag: Optional[List[str]] = None
    protocol: Optional[List[str]] = None
    attrs: Optional[Dict[str, str]] = None
    local_ip: Optional[List[str]] = None
    local_port: Optional[Union[int, str]] = None


@dataclass
class RouterConfig:
    rules: Optional[List[RouterRule]] = None
    domain_strategy: Optional[str] = None
    balancers: Optional[List[BalancingRule]] = None


@dataclass
class Policy:
    handshake: Optional[int] = None
    conn_idle: Optional[int] = None
    uplink_only: Optional[int] = None
    downlink_only: Optional[int] = None
    stats_user_uplink: Optional[bool] = None
    stats_user_downlink: Optional[bool] = None
    stats_user_online: Optional[bool] = None
    buffer_size: Optional[int] = None


@dataclass
class SystemPolicy:
    stats_inbound_uplink: Optional[bool] = None
    stats_inbound_downlink: Optional[bool] = None
    stats_outbound_uplink: Optional[bool] = None
    stats_outbound_downlink: Optional[bool] = None


@dataclass
class PolicyConfig:
    levels: Optional[Dict[str, Policy]] = None
    system: Optional[SystemPolicy] = None


@dataclass
class BridgeConfig:
    tag: Optional[str] = None
    domain: Optional[str] = None


@dataclass
class PortalConfig:
    tag: Optional[str] = None
    domain: Optional[str] = None


@dataclass
class ReverseConfig:
    bridges: Optional[List[BridgeConfig]] = None
    portals: Optional[List[PortalConfig]] = None


@dataclass
class FakeDnsPoolElementConfig:
    ip_pool: Optional[str] = None
    pool_size: Optional[int] = None


@dataclass
class FakeDnsConfig:
    pool: Optional[FakeDnsPoolElementConfig] = None
    pools: Optional[List[FakeDnsPoolElementConfig]] = None


@dataclass
class ObservatoryConfig:
    subject_selector: Optional[List[str]] = None
    probe_url: Optional[str] = None
    probe_interval: Optional[Union[str, int]] = None
    enable_concurrency: Optional[bool] = None


@dataclass
class HealthCheckSettings:
    destination: Optional[str] = None
    connectivity: Optional[str] = None
    interval: Optional[Union[str, int]] = None
    sampling: Optional[int] = None
    timeout: Optional[Union[str, int]] = None
    http_method: Optional[str] = None


@dataclass
class BurstObservatoryConfig:
    subject_selector: Optional[List[str]] = None
    ping_config: Optional[HealthCheckSettings] = None


@dataclass
class MetricsConfig:
    tag: Optional[str] = None
    listen: Optional[str] = None


@dataclass
class StatsConfig:
    pass


@dataclass
class VersionConfig:
    min: Optional[str] = None
    max: Optional[str] = None


# --- Root Config ---


@dataclass
class XrayConfig:
    log: Optional[LogConfig] = None
    routing: Optional[RouterConfig] = None
    dns: Optional[DnsConfig] = None
    inbounds: Optional[List[InboundDetourConfig]] = None
    outbounds: Optional[List[OutboundDetourConfig]] = None
    policy: Optional[PolicyConfig] = None
    api: Optional[ApiConfig] = None
    metrics: Optional[MetricsConfig] = None
    stats: Optional[StatsConfig] = None
    reverse: Optional[ReverseConfig] = None
    fake_dns: Optional[FakeDnsConfig] = None
    observatory: Optional[ObservatoryConfig] = None
    burst_observatory: Optional[BurstObservatoryConfig] = None
    version: Optional[VersionConfig] = None
