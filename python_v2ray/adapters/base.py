from abc import ABC, abstractmethod
from typing import Any


class BaseProxyAdapter(ABC):
    CONFIG_TYPE = Any

    @abstractmethod
    def start(self, vendor_path: str, debug_mode: bool) -> None:
        pass

    @abstractmethod
    def stop(self) -> None:
        pass


class NonBatchableProxyAdapter(BaseProxyAdapter):
    @abstractmethod
    def set_config(self, ip: str, port: int, config: Any) -> None:
        pass


class BatchableProxyAdapter(BaseProxyAdapter):
    @abstractmethod
    def add_inbound(self, ip: str, port: int) -> str:
        pass

    @abstractmethod
    def add_outbound(self, port: int, config: Any) -> str:
        pass

    @abstractmethod
    def add_rule(self, inbound_tag: str, outbound_tag: str) -> None:
        pass

    @abstractmethod
    def add_default_config(self) -> None:
        pass
