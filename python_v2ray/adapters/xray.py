import copy
from python_v2ray.adapters.base import BatchableProxyAdapter
from python_v2ray.models.xray_core_config import (
    InboundDetourConfig,
    OutboundDetourConfig,
    RouterRule,
    SocksServerConfig
)
from python_v2ray.xray_config_builder import XrayConfigBuilder
from python_v2ray.xray_core_process import XrayCoreProcess


class XrayClientAdapter(BatchableProxyAdapter):
    CONFIG_TYPE = OutboundDetourConfig

    def __init__(self):
        self.builder = XrayConfigBuilder()
        self.process = None

    def _get_inbound_tag(self, port: int) -> str:
        return f"inbound-{port}"

    def _get_outbound_tag(self, port: int) -> str:
        return f"outbound-{port}"

    def add_inbound(self, ip: str, port: int) -> str:
        tag = self._get_inbound_tag(port)
        self.builder.add_inbound(
            InboundDetourConfig(
                tag=tag,
                port=port,
                listen=ip,
                protocol="socks",
                settings=SocksServerConfig(auth="noauth", udp=True),
            )
        )
        return tag

    def add_outbound(self, port: int, config: OutboundDetourConfig) -> str:
        tag = self._get_outbound_tag(port)
        c_config = copy.deepcopy(config)
        c_config.tag = tag
        self.builder.add_outbound(c_config)
        return tag

    def add_rule(self, inbound_tag: str, outbound_tag: str) -> None:
        self.builder.add_routing_rule(
            RouterRule(
                inbound_tag=[inbound_tag],
                outbound_tag=outbound_tag,
            )
        )

    def add_default_config(self) -> None:
        self.builder.add_outbound(
            OutboundDetourConfig(tag="direct", protocol="freedom")
        )
        self.builder.add_outbound(
            OutboundDetourConfig(tag="block", protocol="blackhole")
        )

    def get_config(self):
        return self.builder.config

    def start(self, vendor_path: str, debug_mode: bool = False) -> None:
        self.process = XrayCoreProcess(vendor_path, self.builder, debug_mode)
        self.process.start()

    def stop(self) -> None:
        if self.process:
            self.process.stop()
            self.process = None
