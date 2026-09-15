from __future__ import annotations

import json
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


LOG_PATH = Path("/var/log/ttorongi/application.json")
MAX_LOG_SIZE = 10 * 1024 * 1024
BACKUP_COUNT = 7

VALID_CATEGORIES = {
    "authentication",
    "rental",
    "operation",
    "security",
    "system",
}

VALID_SEVERITIES = {
    "info",
    "warning",
    "error",
    "critical",
}

VALID_RESULTS = {
    "success",
    "failure",
}


class TtorongiJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event: dict[str, Any] = {
            "timestamp": datetime.now().astimezone().isoformat(
                timespec="milliseconds"
            ),
            "service": getattr(record, "service", "ttorongi-user"),
            "category": getattr(record, "category", "system"),
            "event_type": getattr(record, "event_type", "application_log"),
            "severity": getattr(record, "severity", "info"),
            "result": getattr(record, "result", "success"),
            "source_ip": getattr(record, "source_ip", ""),
            "message": record.getMessage(),
        }

        optional_fields = (
            "user_id",
            "username",
            "bicycle_id",
            "rental_id",
            "station_id",
            "partner_id",
            "request_path",
            "http_method",
            "status_code",
            "error_type",
            "error_message",
        )

        for field in optional_fields:
            value = getattr(record, field, None)
            if value is not None:
                event[field] = value

        return json.dumps(
            event,
            ensure_ascii=False,
            separators=(",", ":"),
            default=str,
        )


def create_app_logger() -> logging.Logger:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("ttorongi.application")
    logger.setLevel(logging.INFO)

    if logger.handlers:
        return logger

    handler = RotatingFileHandler(
        filename=LOG_PATH,
        maxBytes=MAX_LOG_SIZE,
        backupCount=BACKUP_COUNT,
        encoding="utf-8",
    )

    handler.setFormatter(TtorongiJsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False

    return logger


app_logger = create_app_logger()


def write_event(
    *,
    message: str,
    category: str,
    event_type: str,
    severity: str,
    result: str,
    source_ip: str = "",
    service: str = "ttorongi-user",
    **fields: Any,
) -> None:
    if category not in VALID_CATEGORIES:
        raise ValueError(f"지원하지 않는 category: {category}")

    if severity not in VALID_SEVERITIES:
        raise ValueError(f"지원하지 않는 severity: {severity}")

    if result not in VALID_RESULTS:
        raise ValueError(f"지원하지 않는 result: {result}")

    level_map = {
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
        "critical": logging.CRITICAL,
    }

    extra_data: dict[str, Any] = {
        "service": service,
        "category": category,
        "event_type": event_type,
        "severity": severity,
        "result": result,
        "source_ip": source_ip,
    }

    for key, value in fields.items():
        if value is not None:
            extra_data[key] = value

    app_logger.log(
        level_map[severity],
        message,
        extra=extra_data,
    )


def write_exception_event(
    *,
    message: str,
    event_type: str,
    source_ip: str = "",
    service: str = "ttorongi-user",
    exception: Exception | None = None,
    **fields: Any,
) -> None:
    error_type = None

    if exception is not None:
        error_type = type(exception).__name__

    write_event(
        message=message,
        category="system",
        event_type=event_type,
        severity="error",
        result="failure",
        source_ip=source_ip,
        service=service,
        error_type=error_type,
        **fields,
    )
