import re
import sys
import tempfile
from typing import List, Optional
import logging

from .xray_config_builder import XrayConfigBuilder
from .process_manager import ProxyClientProcessManager

# NOTE: api_client import is no longer needed here if get_stats is removed or refactored
# // from .api_client import XrayApiClient


class XrayCoreClient(ProxyClientProcessManager):
    """
    Manages the Xray-core process by inheriting from BaseProcessManager.
    It implements the Xray-specific logic for configuration and startup.
    """

    def __init__(
        self,
        vendor_path: str,
        config_builder: XrayConfigBuilder,
        debug_mode: bool = False,
    ):
        super().__init__(vendor_path, "Xray-core", debug_mode)
        self.config_builder = config_builder
        # self.api_port = api_port #! This logic can be refactored if needed
        # // self._api_client = None

    def _get_start_pattern(self) -> Optional[re.Pattern]:
        return re.compile(r".*core: Xray .* started")

    def _get_executable_name(self) -> str:
        if sys.platform == "win32":
            return "xray.exe"
        if sys.platform == "darwin":
            return "xray_macos"
        return "xray_linux"

    def _get_start_command(self) -> List[str]:
        return [str(self.executable_path), "-c", str(self._config_file_path)]

    def _create_config(self) -> None:
        """Creates a temporary JSON config file for the Xray client."""
        with tempfile.NamedTemporaryFile(
            mode="w", delete=False, suffix=".json", encoding="utf-8"
        ) as f:
            f.write(self.config_builder.to_json())
            self._config_file_path = f.name
        logging.info(
            f"Temporary {self.display_name} config created at: {self._config_file_path}"
        )
