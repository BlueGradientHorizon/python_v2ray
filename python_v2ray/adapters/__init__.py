from python_v2ray.adapters.base import BaseProxyAdapter
from python_v2ray.adapters.hysteria import HysteriaClientAdapter
from python_v2ray.adapters.xray import XrayClientAdapter


KNOWN_ADAPTERS: list[type[BaseProxyAdapter]] = [
    XrayClientAdapter,
    HysteriaClientAdapter
]
