"""Dependency-free Python client for the documented Invock authorization boundary."""

from __future__ import annotations

import json
from typing import Any, Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


MAX_RESPONSE_BYTES = 256 * 1024
MAX_EXECUTION_RESULT_BYTES = 128 * 1024
MAX_RESULT_CONTENT_ITEMS = 128
MAX_RESULT_TEXT_BYTES = 64 * 1024
MAX_RESULT_DEPTH = 16
MAX_RESULT_NODES = 4096
_VERDICTS = {"ALLOW", "BLOCK", "APPROVAL_REQUIRED"}


class InvockHTTPError(RuntimeError):
    """An HTTP failure with the server's bounded, structured response available."""

    def __init__(self, status: int, body: Any) -> None:
        super().__init__(f"Invock request failed with HTTP {status}")
        self.status = status
        self.body = body


def _endpoint(endpoint: str, path: str) -> str:
    parsed = urlparse(endpoint)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Invock endpoint must be a valid HTTP URL")
    base = parsed.path.rstrip("/")
    return f"{parsed.scheme}://{parsed.netloc}{base}/{path.lstrip('/')}"


def _decision(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or value.get("verdict") not in _VERDICTS:
        raise ValueError("Invock response has a malformed verdict")
    reasons = value.get("reasonCodes")
    if not isinstance(reasons, list) or any(not isinstance(reason, str) for reason in reasons):
        raise ValueError("Invock response has malformed reasonCodes")
    result: dict[str, Any] = {"verdict": value["verdict"], "reasonCodes": list(reasons)}
    for key in ("receiptId", "approvalId"):
        if key in value:
            if not isinstance(value[key], str):
                raise ValueError(f"Invock response has a malformed {key}")
            result[key] = value[key]
    if "authorizedArguments" in value:
        if not isinstance(value["authorizedArguments"], dict):
            raise ValueError("Invock response has malformed authorizedArguments")
        result["authorizedArguments"] = dict(value["authorizedArguments"])
    if "containmentRequired" in value:
        if not isinstance(value["containmentRequired"], bool):
            raise ValueError("Invock response has malformed containmentRequired")
        result["containmentRequired"] = value["containmentRequired"]
    return result


def _bounded_json(value: Any, depth: int = 0, state: list[int] | None = None) -> bool:
    if state is None:
        state = [0]
    state[0] += 1
    if depth > MAX_RESULT_DEPTH or state[0] > MAX_RESULT_NODES:
        return False
    if value is None or isinstance(value, bool):
        return True
    if isinstance(value, (int, float)):
        return not isinstance(value, float) or value == value and value not in {float("inf"), float("-inf")}
    if isinstance(value, str):
        return len(value.encode("utf-8")) <= MAX_RESULT_TEXT_BYTES
    if isinstance(value, list):
        return len(value) <= MAX_RESULT_CONTENT_ITEMS and all(_bounded_json(item, depth + 1, state) for item in value)
    if isinstance(value, dict):
        return len(value) <= MAX_RESULT_NODES and all(isinstance(key, str) and len(key) <= 512 and _bounded_json(item, depth + 1, state) for key, item in value.items())
    return False


def _execution(value: Any) -> dict[str, Any]:
    result = _decision(value)
    if result["verdict"] != "ALLOW":
        return result
    if not isinstance(value, dict) or not isinstance(result.get("receiptId"), str) or not isinstance(value.get("result"), dict):
        raise ValueError("Invock execution response is missing receiptId or result")
    raw = value["result"]
    content = raw.get("content")
    if not isinstance(content, list) or not content or len(content) > MAX_RESULT_CONTENT_ITEMS:
        raise ValueError("Invock execution response has malformed result")
    safe_content: list[dict[str, str]] = []
    for item in content:
        if not isinstance(item, dict) or set(item) != {"type", "text"} or item.get("type") != "text" or not isinstance(item.get("text"), str) or len(item["text"].encode("utf-8")) > MAX_RESULT_TEXT_BYTES:
            raise ValueError("Invock execution response has malformed result content")
        safe_content.append({"type": "text", "text": item["text"]})
    if "structuredContent" in raw and (not isinstance(raw["structuredContent"], dict) or not _bounded_json(raw["structuredContent"])):
        raise ValueError("Invock execution response has malformed structuredContent")
    if "isError" in raw and not isinstance(raw["isError"], bool):
        raise ValueError("Invock execution response has malformed isError")
    safe_result: dict[str, Any] = {"content": safe_content}
    if "structuredContent" in raw:
        safe_result["structuredContent"] = dict(raw["structuredContent"])
    if "isError" in raw:
        safe_result["isError"] = raw["isError"]
    if len(json.dumps(safe_result, separators=(",", ":")).encode("utf-8")) > MAX_EXECUTION_RESULT_BYTES:
        raise ValueError("Invock execution result exceeds 128 KiB")
    result["result"] = safe_result
    return result


class InvockClient:
    def __init__(self, endpoint: str, token: str, urlopen_impl: Callable[..., Any] = urlopen) -> None:
        if not token:
            raise ValueError("Invock token must not be empty")
        self._endpoint = endpoint
        self._token = token
        self._urlopen = urlopen_impl

    def _request(self, path: str, method: str, payload: Mapping[str, Any] | None = None) -> Any:
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = Request(_endpoint(self._endpoint, path), data=body, headers=headers, method=method)
        try:
            with self._urlopen(request) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) > MAX_RESPONSE_BYTES:
                    raise ValueError("Invock response exceeds 256 KiB")
                try:
                    return json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as error:
                    raise ValueError("Invock response was not valid JSON") from error
        except HTTPError as error:
            body: Any = None
            try:
                raw = error.read(MAX_RESPONSE_BYTES + 1)
                if len(raw) <= MAX_RESPONSE_BYTES:
                    body = json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError, OSError):
                body = None
            raise InvockHTTPError(error.code, body) from None
        except URLError as error:
            raise RuntimeError("Invock request could not be completed") from error

    def authorize(self, tool: str, arguments: Mapping[str, Any], agent: str | None = None, intent_capsule: Any = None, capability_leases: list[Any] | None = None, session_id: str | None = None, project_id: str | None = None, authority_binding: Any = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"tool": tool, "arguments": dict(arguments)}
        if agent is not None:
            payload["agent"] = agent
        if project_id is not None:
            payload["projectId"] = project_id
        if intent_capsule is not None:
            payload["intentCapsule"] = intent_capsule
        if authority_binding is not None:
            payload["authorityBinding"] = authority_binding
        if capability_leases is not None:
            payload["capabilityLeases"] = capability_leases
        if session_id is not None:
            payload["sessionId"] = session_id
        return _decision(self._request("/api/v1/authorize", "POST", payload))

    def execute(self, tool: str, arguments: Mapping[str, Any], agent: str | None = None, intent_capsule: Any = None, capability_leases: list[Any] | None = None, session_id: str | None = None, project_id: str | None = None, authority_binding: Any = None) -> dict[str, Any]:
        payload: dict[str, Any] = {"tool": tool, "arguments": dict(arguments)}
        if agent is not None:
            payload["agent"] = agent
        if project_id is not None:
            payload["projectId"] = project_id
        if intent_capsule is not None:
            payload["intentCapsule"] = intent_capsule
        if authority_binding is not None:
            payload["authorityBinding"] = authority_binding
        if capability_leases is not None:
            payload["capabilityLeases"] = capability_leases
        if session_id is not None:
            payload["sessionId"] = session_id
        return _execution(self._request("/api/v1/execute", "POST", payload))

    def health(self) -> dict[str, str]:
        value = self._request("/api/v1/health", "GET")
        if not isinstance(value, dict) or not isinstance(value.get("status"), str):
            raise ValueError("Invock health response was malformed")
        return {"status": value["status"]}
