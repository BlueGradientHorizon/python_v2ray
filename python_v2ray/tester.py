import sys
import time
import logging
from pathlib import Path
from typing import List, Generator, Optional, cast
from contextlib import contextmanager

from python_v2ray import engine
from .xray_config_builder import XrayConfigBuilder
from python_v2ray.engine import (
    DownloadSpeedTask,
    DownloadTaskResult,
    EngineTask,
    LatencyTask,
    LatencyTaskResult,
    LatencyTaskSettings,
    TaskResult,
    UploadSpeedTask,
    UploadTaskResult,
)
from python_v2ray.process_manager import ProxyClientProcessManager

from .hysteria import HysteriaClient
from .xray_core import XrayCoreClient
from .profile_parser import ProxyProfile

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s"
)


@contextmanager
def manage_proxies(
    self: "ConnectionTester", tasks: List[EngineTask], **kwargs
) -> Generator[List[EngineTask], None, None]:
    """
    A context manager that manages the lifecycle of proxy processes (Xray, Hysteria)
    for a block of code. It handles setup, teardown, and yields a list of
    proxy tasks to the wrapped function.
    """
    if not tasks:
        yield []
        return
    logging.info(f"Orchestrating proxies...")
    proxies_to_manage: list[ProxyClientProcessManager] = []
    xray_params_to_merge: list[tuple[ProxyProfile, int]] = []
    debug_mode = kwargs.get("debug_mode", False)

    for i, task in enumerate(tasks):
        if task.profile.protocol in ["hysteria", "hysteria2", "hy2"]:
            proxies_to_manage.append(
                HysteriaClient(
                    str(self.vendor_path),
                    task.profile,
                    local_port=task.port,
                    debug_mode=debug_mode,
                )
            )
        else:
            xray_params_to_merge.append((task.profile, task.port))

    if xray_params_to_merge:
        builder = XrayConfigBuilder()
        for i, (task, local_port) in enumerate(xray_params_to_merge):
            internal_xray_outbound_tag = f"proxy_out_xray_{i}"
            builder.add_inbound(
                {
                    "tag": f"inbound-{local_port}",
                    "port": local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": True},
                }
            )
            outbound = builder.build_outbound_from_params(
                task, explicit_tag=internal_xray_outbound_tag
            )
            if outbound:
                builder.add_outbound(outbound)
                builder.config["routing"]["rules"].append(
                    {
                        "type": "field",
                        "inboundTag": [f"inbound-{local_port}"],
                        "outboundTag": outbound["tag"],
                    }
                )
            else:
                logging.warning(
                    f"Skipping Xray outbound for protocol '{task.protocol}' and tag '{task.tag}' (not supported or failed to build)."
                )
        builder.add_outbound({"protocol": "freedom", "tag": "direct"})
        builder.add_outbound({"protocol": "blackhole", "tag": "block"})
        proxies_to_manage.append(
            XrayCoreClient(str(self.vendor_path), builder, debug_mode=debug_mode)
        )

    try:
        logging.info(f"Starting {len(proxies_to_manage)} proxy manager(s)...")
        for proxy in proxies_to_manage:
            proxy.start()

        yield tasks

    finally:
        logging.info("Stopping all proxy managers...")
        for proxy in reversed(proxies_to_manage):
            proxy.stop()


class ConnectionTester:
    def __init__(self, vendor_path: str, core_engine_path: str):
        self.vendor_path = Path(vendor_path)
        self.core_engine_path = Path(core_engine_path)
        if sys.platform == "win32":
            self.tester_exe, self.xray_exe, self.hysteria_exe = (
                "core_engine.exe",
                "xray.exe",
                "hysteria.exe",
            )
        elif sys.platform == "darwin":
            self.tester_exe, self.xray_exe, self.hysteria_exe = (
                "core_engine_macos",
                "xray_macos",
                "hysteria_macos",
            )
        else:
            self.tester_exe, self.xray_exe, self.hysteria_exe = (
                "core_engine_linux",
                "xray_linux",
                "hysteria_linux",
            )
        if not (self.core_engine_path / self.tester_exe).is_file():
            raise FileNotFoundError("Tester executable not found")

    def test_latency(
        self,
        profiles: List[ProxyProfile],
        ip: str = "127.0.0.1",
        base_port: int = 20800,
        task_timeout: float = 10,
        test_timeout: Optional[float] = None,
        ping_url: str = "http://www.google.com/generate_204",
        max_workers: Optional[int] = None,
        settings: LatencyTaskSettings = LatencyTaskSettings(),
        **kwargs,
    ) -> List[LatencyTaskResult]:
        """
        * Takes a list of PRE-PARSED ConfigParams objects and tests them using the correct client.
        * This version is robust against failing individual configs and duplicate tags.
        * It now leverages the manage_proxies context manager to handle Xray/Hysteria lifecycle.
        """
        tasks = []
        for i, prof in enumerate(profiles):
            tasks.append(
                LatencyTask(prof, ip, base_port + i, task_timeout, ping_url, settings)
            )
        with manage_proxies(self, tasks, **kwargs) as tasks_to_run:
            if not tasks_to_run:
                return []
            logging.info(f"Running {len(tasks_to_run)} latency tasks...")
            return cast(
                List[LatencyTaskResult],
                self._run_tasks(tasks_to_run, test_timeout, max_workers),
            )

    def test_download(
        self,
        profiles: List[ProxyProfile],
        ip: str = "127.0.0.1",
        base_port: int = 20800,
        task_timeout: float = 60,
        test_timeout: Optional[float] = None,
        download_url: str = "https://speed.cloudflare.com/__down",
        target_bytes: int = 10 * 1024 * 1024,
        max_workers: Optional[int] = None,
        **kwargs,
    ) -> List[DownloadTaskResult]:
        tasks = []
        for i, prof in enumerate(profiles):
            tasks.append(
                DownloadSpeedTask(
                    prof,
                    ip,
                    base_port + i,
                    task_timeout,
                    download_url,
                    target_bytes,
                )
            )

        with manage_proxies(self, tasks, **kwargs) as tasks_to_run:
            logging.info(f"Running {len(tasks_to_run)} download speed tests...")
            r = self._run_tasks(tasks_to_run, test_timeout, max_workers)
            return cast(List[DownloadTaskResult], r)

    def test_upload(
        self,
        profiles: List[ProxyProfile],
        ip: str = "127.0.0.1",
        base_port: int = 20800,
        task_timeout: float = 60,
        test_timeout: Optional[float] = None,
        upload_url: str = "https://speed.cloudflare.com/__up",
        target_bytes: int = 10 * 1024 * 1024,
        max_workers: Optional[int] = None,
        **kwargs,
    ) -> List[UploadTaskResult]:
        tasks = []
        for i, prof in enumerate(profiles):
            tasks.append(
                UploadSpeedTask(
                    prof,
                    ip,
                    base_port + i,
                    task_timeout,
                    upload_url,
                    target_bytes,
                )
            )

        with manage_proxies(self, tasks, **kwargs) as tasks_to_run:
            logging.info(f"Running {len(tasks_to_run)} upload speed tests...")
            r = self._run_tasks(tasks_to_run, test_timeout, max_workers)
            return cast(List[UploadTaskResult], r)

    def _run_tasks(
        self,
        tasks: List[EngineTask],
        test_timeout: Optional[float],
        max_workers: Optional[int],
    ) -> List[TaskResult]:
        start = time.time()
        if not tasks:
            return []
        try:
            results = engine.execute_tasks(tasks, test_timeout, max_workers)
            print(f"time: {time.time()-start}")
            return results
        except Exception as e:
            logging.error(f"An error occurred while running the network tester: {e}")
            return []

    def _test_individual_clients(
        self,
        profiles: List[ProxyProfile],
        client_exe: str,
        protocol_name: str,
        timeout: int,
        ping_url: str,
    ) -> List[TaskResult]:
        test_tasks = []
        base_port = 30800
        ip_counter = 2
        for i, prof in enumerate(profiles):
            test_tasks.append(
                {
                    "tag": prof.display_tag,
                    "protocol": protocol_name,
                    "config_uri": f"{prof.protocol}://{prof.hy2_password}@{prof.address}:{prof.port}?sni={prof.sni}",
                    "listen_ip": f"127.0.0.{ip_counter}",
                    "test_port": base_port + i,
                    "client_path": str(self.vendor_path / client_exe),
                    "ping_url": ping_url,
                }
            )
            ip_counter += 1
        return self._run_tasks(test_tasks, timeout, None)
