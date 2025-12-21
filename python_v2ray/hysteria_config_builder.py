import json
from typing import Optional

from python_v2ray.models.hysteria_config import HysteriaConfig, Socks5Inbound

from python_v2ray.utils import prune_empty_containers, to_camel_case


class HysteriaConfigBuilder:
    def __init__(self, config: Optional[HysteriaConfig] = None):
        if config is not None:
            self.config = config
        else:
            self.config: HysteriaConfig = HysteriaConfig()

    def set_socks5_inbound(self, inbound_config: Socks5Inbound):
        self.config.socks5 = inbound_config

    # def build_outbound_from_params(
    #     self, params: ProxyProfile
    # ) -> Optional[ProxyProfile]:
    #     aliases = ["hysteria", "hysteria2", "hy2"]
    #     if not params.protocol in aliases:
    #         return None
    #     if not params.outbound:
    #         return None
    #     return params

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(
            to_camel_case(prune_empty_containers(self.config)),
            indent=indent,
            ensure_ascii=False,
        )
