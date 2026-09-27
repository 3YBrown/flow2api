"""Validate exported Google cookies against the current Flow frontend."""

import hashlib
import json
import re
from typing import Any, Dict, Optional

from curl_cffi.requests import AsyncSession

from ..core.logger import debug_logger


FLOW_BASE = "https://flow.google.com"
IMPERSONATE = "chrome136"
GOOGLE_COOKIE_NAMES = ("SID", "HSID", "SSID", "APISID", "SAPISID", "OSID")


def _parse_google_cookies(raw: str) -> Dict[str, str]:
    text = str(raw or "").strip()
    if not text:
        return {}
    if any(ord(character) < 0x20 for character in text):
        return {}
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        data = None

    result: Dict[str, str] = {}
    if isinstance(data, list):
        for item in data:
            if not isinstance(item, dict):
                continue
            domain = str(item.get("domain") or "").strip().lower().lstrip(".")
            if domain and domain not in {"google.com", "flow.google.com"}:
                continue
            name = str(item.get("name") or "").strip()
            value = str(item.get("value") or "").strip()
            if (
                re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name)
                and value
                and ";" not in value
            ):
                result[name] = value
        return result
    if isinstance(data, dict):
        for name, value in data.items():
            normalized_name = str(name or "").strip()
            normalized_value = str(value or "").strip()
            if (
                re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", normalized_name)
                and normalized_value
                and ";" not in normalized_value
            ):
                result[normalized_name] = normalized_value
        return result

    for part in text.replace("\n", ";").split(";"):
        name, separator, value = part.strip().partition("=")
        if (
            separator
            and re.fullmatch(r"[!#$%&'*+\-.^_`|~0-9A-Za-z]+", name.strip())
            and value.strip()
            and ";" not in value
        ):
            result[name.strip()] = value.strip()
    return result


def _build_cookie_header(cookies: Dict[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


class ProtocolLogin:
    """Check that exported cookies can load the current Flow application."""

    async def login(
        self,
        google_cookies_raw: str,
        proxy: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Dict[str, Any]:
        google_cookies = _parse_google_cookies(google_cookies_raw)
        if not any(name in google_cookies for name in GOOGLE_COOKIE_NAMES):
            return {
                "success": False,
                "error": "未找到有效的 Google Cookie",
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
                        "Cookie": _build_cookie_header(google_cookies),
                        "Referer": f"{FLOW_BASE}/",
                    },
                )
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
