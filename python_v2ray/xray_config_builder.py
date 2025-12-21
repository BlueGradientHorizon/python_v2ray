from dataclasses import asdict, fields, is_dataclass
from enum import Enum
import json
from typing import Optional, Any

from python_v2ray.models.xray_core_config import (
    InboundDetourConfig,
    LogConfig,
    LogLevel,
    MuxConfig,
    OutboundDetourConfig,
    Policy,
    PolicyConfig,
    RouterConfig,
    RouterRule,
    StatsConfig,
    SystemPolicy,
    XrayConfig,
)
from python_v2ray.utils import prune_empty_containers, to_camel_case


class XrayConfigBuilder:
    def __init__(self):
        self.config: XrayConfig = XrayConfig()
        self.config.log = LogConfig(loglevel=LogLevel.WARNING)
        self.config.stats = StatsConfig()
        self.config.policy = PolicyConfig(
            system=SystemPolicy(
                stats_inbound_uplink=True,
                stats_inbound_downlink=True,
                stats_outbound_uplink=True,
                stats_outbound_downlink=True,
            ),
            levels={"0": Policy(stats_user_uplink=True, stats_user_downlink=True)},
        )
        # self.warp_outbound_tag: Optional[str] = None

    def add_inbound(self, inbound_config: InboundDetourConfig):
        if not self.config.inbounds:
            self.config.inbounds = []
        self.config.inbounds.append(inbound_config)

    def add_outbound(self, outbound_config: OutboundDetourConfig):
        if not self.config.outbounds:
            self.config.outbounds = []
        self.config.outbounds.append(outbound_config)

    def add_routing_rule(self, rule: RouterRule):
        if not self.config.routing:
            self.config.routing = RouterConfig()
        if self.config.routing.rules:
            self.config.routing.rules.append(rule)
        else:
            self.config.routing.rules = [rule]

    # def build_outbound_from_params(
    #     self, params: ProxyProfile, explicit_tag: str
    # ) -> Optional[ProxyProfile]:
    #     protocol_map = {
    #         "vless": "vless",
    #         "mvless": "vless",
    #         "vmess": "vmess",
    #         "trojan": "trojan",
    #         "ss": "shadowsocks",
    #         "socks": "socks",
    #         "wireguard": "wireguard",
    #     }
    #     xray_protocol_name = protocol_map.get(params.protocol)
    #     if not xray_protocol_name:
    #         return None
    #     if not params.outbound:
    #         return None
    #     params.outbound.tag = explicit_tag
    #     # if params.protocol == "mvless" and params.mux_enabled:
    #     #     params.outbound.mux = MuxConfig(True, params.mux_concurrency)
    #     # if self.warp_outbound_tag and params.tag != self.warp_outbound_tag:
    #     # outbound.streamSettings.sockopt = Sockopt(self.warp_outbound_tag)
    #     return params

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            to_camel_case(prune_empty_containers(self.config)),
            indent=indent,
            ensure_ascii=False,
        )
