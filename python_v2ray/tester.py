import sys
import time
import logging
from pathlib import Path
from typing import Callable, List, Generator, Optional, cast
from contextlib import contextmanager

from python_v2ray import engine
from python_v2ray.adapters import KNOWN_ADAPTERS
from python_v2ray.adapters.base import (
    BaseProxyAdapter,
    BatchableProxyAdapter,
    NonBatchableProxyAdapter,
)
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
    debug_mode = kwargs.get("debug_mode", False)

    batchable_tasks: dict[type[BatchableProxyAdapter], list[EngineTask]] = {}
    nonbatchable_tasks: list[tuple[type[NonBatchableProxyAdapter], EngineTask]] = []

    adapters: list[BaseProxyAdapter] = []

    for task in tasks:
        if task.profile.outbound_config is None:
            logging.warning(
                f"Skipping outbound configuration for protocol '{task.profile.protocol}' and inbound port {task.port}."
            )
            continue
        config_type = type(task.profile.outbound_config)
        adapter_type = None
        for known_adapter_type in KNOWN_ADAPTERS:
            if known_adapter_type.CONFIG_TYPE != config_type:
                continue
            adapter_type = known_adapter_type
        if adapter_type is None:
            print("unknown adapter")
            continue
        match adapter_type:
            case _ if issubclass(adapter_type, BatchableProxyAdapter):
                if batchable_tasks.get(adapter_type) is None:
                    batchable_tasks[adapter_type] = []
                batchable_tasks[adapter_type].append(task)
            case _ if issubclass(adapter_type, NonBatchableProxyAdapter):
                nonbatchable_tasks.append((adapter_type, task))
            case _:
                print("unknown adapter")

    for known_adapter_type, batch_tasks in batchable_tasks.items():
        adapter = known_adapter_type()
        adapter.add_default_config()
        for task in batch_tasks:
            i_tag = adapter.add_inbound(task.ip, task.port)
            o_tag = adapter.add_outbound(task.port, task.profile.outbound_config)
            adapter.add_rule(i_tag, o_tag)
        adapters.append(adapter)

    for known_adapter_type, task in nonbatchable_tasks:
        known_adapter_type = known_adapter_type()
        known_adapter_type.set_config(task.ip, task.port, task.profile.outbound_config)
        adapters.append(known_adapter_type)

    try:
        logging.info(f"Starting {len(adapters)} proxy manager(s)...")
        for adapter in adapters:
            adapter.start(str(self.vendor_path), debug_mode)

        yield tasks

    finally:
        logging.info("Stopping all proxy managers...")
        for adapter in adapters:
            adapter.stop()


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
        on_result: Optional[Callable[[TaskResult], None]] = None,
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
                self._run_tasks(tasks_to_run, test_timeout, max_workers, on_result),
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
        on_result: Optional[Callable[[TaskResult], None]] = None,
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
            r = self._run_tasks(tasks_to_run, test_timeout, max_workers, on_result)
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
        on_result: Optional[Callable[[TaskResult], None]] = None,
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
            r = self._run_tasks(tasks_to_run, test_timeout, max_workers, on_result)
            return cast(List[UploadTaskResult], r)

    def _run_tasks(
        self,
        tasks: List[EngineTask],
        test_timeout: Optional[float],
        max_workers: Optional[int],
        on_result: Optional[Callable[[TaskResult], None]] = None,
    ) -> List[TaskResult]:
        start = time.time()
        if not tasks:
            return []
        try:
            results = engine.execute_tasks(tasks, test_timeout, max_workers, on_result)
            print(f"time: {time.time()-start}")
            return results
        except Exception as e:
            logging.error(f"An error occurred while running the network tester: {e}")
            return []

    # def _test_individual_clients(
    #     self,
    #     profiles: List[ProxyProfile],
    #     client_exe: str,
    #     protocol_name: str,
    #     timeout: int,
    #     ping_url: str,
    # ) -> List[TaskResult]:
    #     test_tasks = []
    #     base_port = 30800
    #     ip_counter = 2
    #     for i, prof in enumerate(profiles):
    #         test_tasks.append(
    #             {
    #                 "tag": prof.display_tag,
    #                 "protocol": protocol_name,
    #                 "config_uri": f"{prof.protocol}://{prof.hy2_password}@{prof.address}:{prof.port}?sni={prof.sni}",
    #                 "listen_ip": f"127.0.0.{ip_counter}",
    #                 "test_port": base_port + i,
    #                 "client_path": str(self.vendor_path / client_exe),
    #                 "ping_url": ping_url,
    #             }
    #         )
    #         ip_counter += 1
    #     return self._run_tasks(test_tasks, timeout, None)
