"""Validate exported Google cookies against the current Flow frontend."""

import hashlib
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from curl_cffi.requests import AsyncSession

from ..core.logger import debug_logger
from .browser_cookie_utils import validate_flow_cookie_storage


FLOW_BASE = "https://flow.google.com"
IMPERSONATE = "chrome"


class ProtocolLogin:
    """Check that exported cookies can load the current Flow application."""

    async def login(
        self,
        google_cookies_raw: str,
        proxy: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Dict[str, Any]:
        try:
            cookie_header = validate_flow_cookie_storage(google_cookies_raw)
        except ValueError as exc:
            return {
                "success": False,
                "error": str(exc),
            }

        session_kwargs: Dict[str, Any] = {
            "impersonate": IMPERSONATE,
            "trust_env": False,
        }
        normalized_proxy = str(proxy or "").strip()
        if normalized_proxy:
            if "://" not in normalized_proxy:
                normalized_proxy = f"http://{normalized_proxy}"
            session_kwargs["proxy"] = normalized_proxy

        try:
            async with AsyncSession(**session_kwargs) as session:
                response = await session.get(
                    f"{FLOW_BASE}/projects",
                    headers={
                        "Cookie": cookie_header,
                        "Referer": f"{FLOW_BASE}/",
                    },
                )
            response_host = str(urlparse(str(response.url)).hostname or "").lower()
            if response_host and response_host != "flow.google.com":
                return {
                    "success": False,
                    "error": "Flow Cookie 已失效或不完整，页面已跳转到 Google 登录",
                }
            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"Flow Cookie 验证失败: HTTP {response.status_code}",
                }
            if "boq_labs-ai-sandbox-frontend_" not in (response.text or ""):
                return {
                    "success": False,
                    "error": "Flow Cookie 验证失败: 未加载当前前端",
                }
            digest = hashlib.sha256(google_cookies_raw.encode("utf-8")).hexdigest()[:32]
            return {
                "success": True,
                "session_token": f"frontend-{digest}",
                "email": str(email or "").strip(),
            }
        except Exception as exc:
            debug_logger.log_error(f"[PROTOCOL_LOGIN] Flow Cookie 验证异常: {exc}")
            return {"success": False, "error": str(exc)}


protocol_loginer = ProtocolLogin()
