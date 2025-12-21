from contextlib import nullcontext
from dataclasses import dataclass
from enum import Enum, auto
import time
import asyncio
from typing import Callable, List, Optional

import aiohttp
from aiohttp_socks import ProxyConnector

from python_v2ray.profile_parser import ProxyProfile


@dataclass
class EngineTask:
    profile: ProxyProfile
    ip: str
    port: int
    timeout: float


@dataclass
class _SpeedTask(EngineTask):
    url: str
    target_bytes: int


@dataclass
class DownloadSpeedTask(_SpeedTask):
    pass


@dataclass
class UploadSpeedTask(_SpeedTask):
    pass


@dataclass
class LatencyTaskSettings:
    max_attempts: int = 3
    fail_immediately: bool = False
    retry_delay: Optional[float] = 0.2


@dataclass
class LatencyTask(EngineTask):
    ping_url: str
    settings: LatencyTaskSettings


@dataclass
class TaskResult:
    profile: ProxyProfile
    # status: str


class SpeedTaskStatus(Enum):
    UNKNOWN = auto()
    SUCCESS = auto()
    FAILURE = auto()
    BAD_HTTP_STATUS = auto()


@dataclass
class UploadTaskResult(TaskResult):
    status: SpeedTaskStatus
    error: Optional[str]
    upload_mbps: Optional[float]
    bytes_uploaded: Optional[int]


@dataclass
class DownloadTaskResult(TaskResult):
    status: SpeedTaskStatus
    error: Optional[str]
    download_mbps: Optional[float]
    bytes_downloaded: Optional[int]


class LatencyTaskStatus(Enum):
    UNKNOWN = auto()
    SUCCESS = auto()
    PARTIAL_SUCCESS = auto()
    FAILURE = auto()


@dataclass
class LatencyTaskPingResult:
    ping: Optional[int]
    error: Optional[str]


@dataclass
class LatencyTaskResult(TaskResult):
    status: LatencyTaskStatus
    best_ping: Optional[int]
    worst_ping: Optional[int]
    ping_results: list[LatencyTaskPingResult]


async def zero_stream_generator(size: int):
    generated = 0
    chunk_size = 65536
    while generated < size:
        remaining = size - generated
        to_yield = min(chunk_size, remaining)
        generated += to_yield
        yield b"\x00" * to_yield


def _get_connector(listen_ip: str, test_port: int) -> ProxyConnector:
    socks_url = f"socks5://{listen_ip}:{test_port}"
    return ProxyConnector.from_url(socks_url, ssl=False)


async def run_upload_test(task: UploadSpeedTask) -> UploadTaskResult:
    profile = task.profile
    result = UploadTaskResult(
        profile=profile,
        status=SpeedTaskStatus.UNKNOWN,
        error=None,
        upload_mbps=None,
        bytes_uploaded=None,
    )

    try:
        url = task.url
        total_bytes = task.target_bytes
        connector = _get_connector(task.ip, task.port)

        headers = {"Content-Type": "application/octet-stream"}

        start_time = time.perf_counter()

        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.post(
                url,
                data=zero_stream_generator(total_bytes),
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=task.timeout),
            ) as resp:
                duration = time.perf_counter() - start_time

                if resp.status != 200:
                    result.status = SpeedTaskStatus.BAD_HTTP_STATUS
                    result.error = f"bad status {resp.status}"
                    return result

                upload_mbps = (total_bytes * 8) / (duration * 1024 * 1024)

                result.status = SpeedTaskStatus.SUCCESS
                result.upload_mbps = upload_mbps
                result.bytes_uploaded = total_bytes
                return result

    except Exception as e:
        result.status = SpeedTaskStatus.FAILURE
        result.error = str(e)
        return result


async def run_download_test(task: DownloadSpeedTask) -> DownloadTaskResult:
    profile = task.profile
    result = DownloadTaskResult(
        profile=profile,
        status=SpeedTaskStatus.UNKNOWN,
        error=None,
        download_mbps=None,
        bytes_downloaded=None,
    )

    try:
        base_url = task.url
        total_bytes_target = task.target_bytes
        full_url = f"{base_url}?bytes={total_bytes_target}"
        connector = _get_connector(task.ip, task.port)

        start_time = time.perf_counter()

        async with aiohttp.ClientSession(connector=connector) as session:
            async with session.get(
                full_url, timeout=aiohttp.ClientTimeout(total=task.timeout)
            ) as resp:
                if resp.status != 200:
                    result.status = SpeedTaskStatus.BAD_HTTP_STATUS
                    result.error = f"bad status {resp.status}"
                    return result

                bytes_downloaded = 0
                async for chunk in resp.content.iter_chunked(32768):
                    bytes_downloaded += len(chunk)

                duration = time.perf_counter() - start_time

                speed_mbps = (bytes_downloaded * 8) / (duration * 1024 * 1024)

                result.status = SpeedTaskStatus.SUCCESS
                result.download_mbps = speed_mbps
                result.bytes_downloaded = bytes_downloaded
                return result

    except Exception as e:
        result.status = SpeedTaskStatus.FAILURE
        result.error = str(e)
        return result


async def run_latency_test(task: LatencyTask) -> LatencyTaskResult:
    profile = task.profile
    listen_ip = task.ip
    test_port = task.port
    ping_url = task.ping_url

    result = LatencyTaskResult(
        profile=profile,
        status=LatencyTaskStatus.UNKNOWN,
        best_ping=None,
        worst_ping=None,
        ping_results=[],
    )

    for _ in range(task.settings.max_attempts):
        try:
            connector = _get_connector(listen_ip, test_port)
            async with aiohttp.ClientSession(connector=connector) as session:
                start = time.perf_counter()
                async with session.get(
                    ping_url, timeout=aiohttp.ClientTimeout(total=task.timeout)
                ) as resp:
                    duration_ms = int((time.perf_counter() - start) * 1000)

                    if resp.status not in [200, 204]:
                        if d := task.settings.retry_delay:
                            await asyncio.sleep(d)
                        result.ping_results.append(
                            LatencyTaskPingResult(None, f"bad status {resp.status}")
                        )
                        continue

                    result.ping_results.append(LatencyTaskPingResult(duration_ms, None))

        except Exception as e:
            result.ping_results.append(
                LatencyTaskPingResult(None, str(e.__class__) + str(e))
            )
            if task.settings.fail_immediately:
                break
            else:
                if d := task.settings.retry_delay:
                    await asyncio.sleep(d)
                continue

    sorted_by_ping = sorted(
        result.ping_results,
        key=lambda x: (x.ping is None, x.ping if x.ping is not None else 0),
    )
    if (l := len(sorted_by_ping)) > 0:
        result.best_ping = sorted_by_ping[0].ping
        result.worst_ping = sorted_by_ping[l - 1].ping

    none_pings_count = sum(1 for r in result.ping_results if r.ping is None)

    if none_pings_count == 0 and len(result.ping_results) > 0:
        result.status = LatencyTaskStatus.SUCCESS
    elif none_pings_count > 0 and none_pings_count < len(result.ping_results):
        result.status = LatencyTaskStatus.PARTIAL_SUCCESS
    elif none_pings_count == len(result.ping_results):
        result.status = LatencyTaskStatus.FAILURE

    return result


_TASK_MAP = {
    DownloadSpeedTask: run_download_test,
    UploadSpeedTask: run_upload_test,
    LatencyTask: run_latency_test,
}


async def _run_with_semaphore(
    sem: asyncio.Semaphore | nullcontext[None], handler, *args, **kwargs
):
    async with sem:
        return await handler(*args, **kwargs)


def execute_tasks(
    tasks: List[EngineTask],
    timeout: Optional[float],
    max_workers: Optional[int],
    on_result: Optional[Callable[[TaskResult], None]] = None,
) -> List[TaskResult]:
    async def _execute_jobs_async(
        tasks: List[EngineTask], timeout: Optional[float]
    ) -> List[TaskResult]:
        sem = (
            asyncio.Semaphore(max_workers)
            if max_workers and max_workers > 0
            else nullcontext()
        )
        async_tasks: List[asyncio.Task] = []
        for i, task in enumerate(tasks):
            handler = _TASK_MAP.get(type(task))
            if handler:
                t = asyncio.create_task(_run_with_semaphore(sem, handler, task))
                if on_result is not None:
                    def callback_wrapper(fut: asyncio.Future):
                        try:
                            if not fut.cancelled():
                                on_result(fut.result()) # type: ignore
                        except Exception:
                            pass

                    t.add_done_callback(callback_wrapper)
                async_tasks.append(t)
        done, pending = await asyncio.wait(async_tasks, timeout=timeout)
        results = [d.result() for d in done]
        for p in pending:
            p.cancel()

        return results

    return asyncio.run(_execute_jobs_async(tasks, timeout))
