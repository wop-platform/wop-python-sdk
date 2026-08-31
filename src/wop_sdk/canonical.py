# -*- coding: utf-8 -*-
"""canonicalRequest 构造（F2）。

结构（5 段 '\\n' 连接，对照网关 CanonicalRequestBuilder）：

    authString\\nHTTPMethod\\ncanonicalURI\\ncanonicalQueryString\\ncanonicalHeaders

POST 的 canonicalQueryString 为空字符串（分隔空行不可省略）；
header 值编码 = Java URLEncoder 语义（空格 → %20）。
"""
from typing import Dict, Optional

from .encoding import java_urlencode, trimall


def canonical_headers(headers: Optional[Dict[str, str]]) -> str:
    """规范标头：名称 lowercase+trimall+urlencode，值 trimall+urlencode，
    名称 ASCII 升序，行间 '\\n' 连接，尾行不加 '\\n'。"""
    if not headers:
        return ""
    normalized = {
        trimall(name).lower(): trimall(value)
        for name, value in headers.items()
    }
    return "\n".join(
        f"{java_urlencode(k)}:{java_urlencode(normalized[k])}"
        for k in sorted(normalized)
    )


def build_canonical(
    auth_string: Optional[str],
    method: Optional[str],
    canonical_uri: Optional[str],
    query_string: Optional[str],
    canonical_headers: Optional[str],
) -> str:
    """组装规范请求（5 段）；None 段落输出空串，保持 5 段结构。"""
    safe_method = (method or "").strip().upper()
    return "\n".join(
        [
            auth_string or "",
            safe_method,
            canonical_uri or "",
            query_string or "",
            canonical_headers or "",
        ]
    )
