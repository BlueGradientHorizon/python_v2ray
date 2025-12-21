import json
import re
import sys
import tempfile
from typing import List, Optional
import logging

from python_v2ray.hysteria_config_builder import HysteriaConfigBuilder

from .process_manager import ProxyClientProcessManager


class HysteriaProcess(ProxyClientProcessManager):
    """
    Manages a standalone Hysteria process by inheriting from BaseProcessManager.
    """

    def __init__(
        self,
        vendor_path: str,
        config_builder: HysteriaConfigBuilder,
        debug_mode: bool = False,
    ):
        super().__init__(vendor_path, "Hysteria", debug_mode)
        self.config_builder = config_builder

    def _get_start_pattern(self) -> Optional[re.Pattern]:
        return re.compile(r".*connected to server.*")

    def _get_executable_name(self) -> str:
        if sys.platform == "win32":
            return "hysteria.exe"
        if sys.platform == "darwin":
            return "hysteria_macos"
        return "hysteria_linux"

    def _get_start_command(self) -> List[str]:
        return [str(self.executable_path), "client", "-c", str(self._config_file_path)]

    def _create_config(self) -> None:
        """Creates a temporary JSON config file for the Hysteria client."""
        # config = {
        #     "server": f"{self.profile.address}:{self.profile.port}",
        #     "auth": self.profile.hy2_password,
        #     "socks5": {"listen": f"127.0.0.1:{self.local_port}"},
        #     "tls": {
        #         "sni": self.profile.sni,
        #         "insecure": True,  # Typically needed for client-side testing
        #     },
        # }
        # if self.profile.hy2_obfs:
        #     config["obfs"] = {
        #         "type": self.profile.hy2_obfs,
        #         "password": self.profile.hy2_obfs_password,
        #     }

        # config_path = self.vendor_path / "hysteria_config.json"
        # with open(config_path, "w", encoding="utf-8") as f:
        #     json.dump(config, f, indent=2)

        # self._config_file_path = str(config_path)
        # logging.info(
        #     f"Temporary {self.display_name} config created at: {self._config_file_path}"
        # )
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".json", encoding="utf-8"
        ) as f:
            f.write(self.config_builder.to_json())
            self._config_file_path = f.name
        logging.info(
            f"Temporary {self.display_name} config created at: {self._config_file_path}"
        )
