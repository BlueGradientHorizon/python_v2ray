import abc
import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional
import logging
import time


class ProxyClientProcessManager(abc.ABC):
    def __init__(self, vendor_path: str, display_name: str, keep_config: bool):
        self.vendor_path = Path(vendor_path)
        self.display_name = display_name
        self.keep_config = keep_config
        self.executable_path = self.vendor_path / self._get_executable_name()
        self.process: Optional[subprocess.Popen] = None
        self._config_file_path: Optional[str] = None
        if not self.executable_path.is_file():
            raise FileNotFoundError(f"Executable not found at: {self.executable_path}")

    @abc.abstractmethod
    def _get_start_pattern(self) -> Optional[re.Pattern]:
        return None

    @abc.abstractmethod
    def _get_executable_name(self) -> str:
        pass

    @abc.abstractmethod
    def _get_start_command(self) -> List[str]:
        pass

    @abc.abstractmethod
    def _create_config(self) -> None:
        pass

    def _cleanup_config(self) -> None:
        if self.keep_config:
            logging.info(
                f"{self.display_name} temporary config file kept at: {self._config_file_path}"
            )
            return
        if self._config_file_path and os.path.exists(self._config_file_path):
            try:
                os.remove(self._config_file_path)
                logging.debug(f"Config file deleted: {self._config_file_path}")
                self._config_file_path = None
            except OSError as e:
                logging.error(
                    f"Error removing config file {self._config_file_path}: {e}"
                )

    def start(self) -> None:
        if self.is_running():
            logging.info(f"{self.display_name} is already running.")
            return

        self._create_config()
        command = self._get_start_command()
        logging.info(f"Starting {self.display_name} with command: {' '.join(command)}")

        bufsize = -1
        pat = self._get_start_pattern()
        if pat:
            bufsize = 1
        try:
            self.process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                bufsize=bufsize,
            )
            log: str = ""
            if not pat:
                time.sleep(0.5)
            else:
                while True:
                    if not self.process.stdout:
                        break

                    line = self.process.stdout.readline()
                    if not line:
                        self.process.wait()
                        break
                    log += line

                    if pat.search(line):
                        logging.info(
                            f"Captured start message of {self.display_name} with PID: {self.process.pid}"
                        )
                        break

            if self.process.poll() is not None:
                logging.error(
                    f"{self.display_name} (PID: {self.process.pid}) exited immediately with code {self.process.returncode}"
                )

                if pat:
                    logging.error(f"--- CAPTURED STDOUT+STDERR ---\n\n{log}")
                    logging.error("-" * 31)
                else:
                    stdout_data, _ = self.process.communicate()
                    if stdout_data:
                        logging.error(
                            f"--- CAPTURED STDOUT+STDERR ---\n\n{stdout_data.strip()}"
                        )
                        logging.error("-" * 31)

                self.process = None
                self._cleanup_config()
                return

            logging.info(
                f"{self.display_name} started successfully with PID: {self.process.pid}"
            )
        except Exception as e:
            logging.error(f"Failed to start {self.display_name}: {e}", exc_info=True)
            self.process = None
            self._cleanup_config()

    def stop(self) -> None:
        if not self.is_running():
            return
        if self.process:
            logging.info(f"Stopping {self.display_name} with PID: {self.process.pid}")
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                logging.warning(f"{self.display_name} was killed forcefully")
            finally:
                self.process = None
        self._cleanup_config()  # Cleanup happens in __exit__ or here

    def is_running(self) -> bool:
        return self.process is not None and self.process.poll() is None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop()
