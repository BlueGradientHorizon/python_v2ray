from python_v2ray.adapters.base import NonBatchableProxyAdapter
from python_v2ray.models.hysteria_config import HysteriaConfig, Socks5Inbound
from python_v2ray.hysteria_config_builder import HysteriaConfigBuilder
from python_v2ray.hysteria_process import HysteriaProcess


class HysteriaClientAdapter(NonBatchableProxyAdapter):
    CONFIG_TYPE = HysteriaConfig

    def __init__(self):
        self.builder = HysteriaConfigBuilder()
        self.process = None

    def set_config(self, ip: str, port: int, config: HysteriaConfig) -> None:
        self.builder.config = config
        self.builder.set_socks5_inbound(Socks5Inbound(listen=f"{ip}:{port}"))

    def get_config(self):
        return self.builder.config

    def start(self, vendor_path: str, debug_mode: bool = False) -> None:
        self.process = HysteriaProcess(vendor_path, self.builder, debug_mode)
        self.process.start()

    def stop(self) -> None:
        if self.process:
            self.process.stop()
            self.process = None
