"""Async HTTP client with retry, logging, and security analysis."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

import httpx

from http_auditor_ultra.config import AuditorConfig
from http_auditor_ultra.utils import (
    AuditStatistics,
    RetryState,
    Timer,
    is_retryable,
    rate_limit_sleep,
)

logger = logging.getLogger(__name__)


@dataclass
class AuditResult:
    """Result of auditing a single URL — Ultra edition."""

    url: str
    status_code: int = 0
    response_time: float = 0.0
    headers: Dict[str, str] = field(default_factory=dict)
    content_length: int = -1
    server: Optional[str] = None
    redirect_url: Optional[str] = None
    error: Optional[str] = None
    retries: int = 0

    # Ultra analysis fields
    body_snippet: str = ""
    security_headers: Dict[str, Any] = field(default_factory=dict)
    waf_name: Optional[str] = None
    tech_stack: List[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def redirected(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def client_error(self) -> bool:
        return 400 <= self.status_code < 500

    @property
    def server_error(self) -> bool:
        return 500 <= self.status_code < 600

    def to_dict(self) -> Dict[str, object]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "success": self.success,
            "response_time_seconds": round(self.response_time, 4),
            "content_length": self.content_length,
            "server": self.server or "",
            "redirect_url": self.redirect_url or "",
            "error": self.error or "",
            "retries": self.retries,
            "http_method": "GET",
            "waf_detected": self.waf_name or "",
            "tech_stack": self.tech_stack,
            "security_headers": self.security_headers,
        }

    def to_csv_row(self) -> Dict[str, object]:
        d = self.to_dict()
        d["tech_stack"] = "; ".join(self.tech_stack) if self.tech_stack else ""
        d.pop("security_headers", None)
        return d


class HttpClient:
    """Async HTTP client wrapper with retry, timeout, and logging."""

    def __init__(self, config: AuditorConfig) -> None:
        self._config: AuditorConfig = config
        self._client: Optional[httpx.AsyncClient] = None
        self._stats: AuditStatistics = AuditStatistics()

    async def __aenter__(self) -> HttpClient:
        limits = httpx.Limits(
            max_connections=self._config.max_concurrent,
            max_keepalive_connections=self._config.max_concurrent,
        )
        timeout = httpx.Timeout(self._config.timeout)
        headers: Dict[str, str] = {
            "User-Agent": self._config.user_agent,
            "Accept": "*/*",
            "Accept-Language": "en-US,en;q=0.5",
            **self._config.headers,
        }
        self._client = await httpx.AsyncClient(
            limits=limits,
            timeout=timeout,
            headers=headers,
            verify=self._config.verify_ssl,
            follow_redirects=self._config.follow_redirects,
        ).__aenter__()
        return self

    async def __aexit__(self, *args: object) -> None:
        if self._client is not None:
            await self._client.__aexit__(*args)
            self._client = None

    @property
    def stats(self) -> AuditStatistics:
        return self._stats

    @property
    def config(self) -> AuditorConfig:
        return self._config

    async def audit_url(self, url: str, method: str = "GET", collect_body: bool = True) -> AuditResult:
        state = RetryState(
            max_retries=self._config.max_retries,
            backoff=self._config.backoff_factor,
        )
        last_error: Optional[str] = None
        last_status: int = 0

        while not state.is_exhausted:
            import time
            t0 = time.monotonic()
            try:
                assert self._client is not None
                response = await self._client.request(method, url)
                elapsed = time.monotonic() - t0

                body_text = ""
                if collect_body:
                    try:
                        body_text = response.text[:500]
                    except Exception:
                        body_text = "<binary>"

                result = AuditResult(
                    url=url,
                    status_code=response.status_code,
                    response_time=elapsed,
                    headers={k.lower(): v for k, v in response.headers.items()},
                    content_length=len(response.content),
                    server=response.headers.get("server"),
                    redirect_url=str(response.url) if response.url else None,
                    retries=state.attempt,
                    body_snippet=body_text,
                )

                if is_retryable(response.status_code, method) and not state.is_exhausted:
                    delay = state.delay
                    logger.warning(
                        "Retryable status %d for %s — retry %d/%d in %.2fs",
                        response.status_code, url, state.attempt + 1, self._config.max_retries, delay,
                    )
                    self._stats.retried += 1
                    last_status = response.status_code
                    await asyncio.sleep(delay)
                    state = state.next()
                    continue

                self._record_success(result)
                return result

            except httpx.TimeoutException as exc:
                elapsed = time.monotonic() - t0
                logger.warning("Timeout for %s after %.2fs — retry %d/%d", url, elapsed, state.attempt + 1, self._config.max_retries)
                last_error = f"Timeout: {exc}"
                self._stats.retried += 1
                await asyncio.sleep(state.delay)
                state = state.next()

            except httpx.HTTPError as exc:
                elapsed = time.monotonic() - t0
                logger.warning("HTTP error for %s: %s — retry %d/%d", url, exc, state.attempt + 1, self._config.max_retries)
                last_error = f"HTTP error: {exc}"
                self._stats.retried += 1
                await asyncio.sleep(state.delay)
                state = state.next()

            except (OSError, asyncio.CancelledError) as exc:
                elapsed = time.monotonic() - t0
                logger.error("System error for %s: %s", url, exc)
                last_error = f"System error: {exc}"
                await asyncio.sleep(state.delay)
                state = state.next()

        if last_status and not last_error:
            error_result = AuditResult(
                url=url,
                status_code=last_status,
                error=f"Max retries exceeded with status {last_status}",
                retries=state.attempt,
            )
        else:
            error_result = AuditResult(
                url=url,
                error=last_error or "Max retries exceeded",
                retries=state.attempt,
            )
        self._record_failure(error_result)
        return error_result

    async def audit_urls(
        self,
        urls: List[str],
        method: str = "GET",
        progress_callback: Optional[Callable[[int, int], Any]] = None,
    ) -> List[AuditResult]:
        total = len(urls)
        results: List[Optional[AuditResult]] = [None] * total
        processed = 0
        sem = asyncio.Semaphore(self._config.max_concurrent)

        async def _audit_one(index: int, url: str) -> None:
            nonlocal processed
            async with sem:
                await rate_limit_sleep(self._config.rate_limit_delay)
                result = await self.audit_url(url, method)
                results[index] = result
                processed += 1
                if progress_callback is not None:
                    cb_result = progress_callback(processed, total)
                    if asyncio.iscoroutine(cb_result):
                        await cb_result

        tasks = [asyncio.create_task(_audit_one(i, u)) for i, u in enumerate(urls)]
        await asyncio.gather(*tasks, return_exceptions=True)
        self._stats.total_urls = total
        return [r for r in results if r is not None]

    def _record_success(self, result: AuditResult) -> None:
        self._stats.successful += 1
        self._stats.total_urls += 1
        self._stats.record_status(result.status_code)

    def _record_failure(self, result: AuditResult) -> None:
        self._stats.failed += 1
        self._stats.total_urls += 1
        if result.error:
            self._stats.errors.append(f"{result.url}: {result.error}")
