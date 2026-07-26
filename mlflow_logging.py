"""MLflow tool-call logging for the Hayabusa MCP server.

Wraps MCP tool functions so each call is recorded as an MLflow run:
call params, a user/tool tag, and any numeric/short-string fields from
the tool's returned dict as metrics/tags. Logging failures never break
the wrapped tool.
"""

from __future__ import annotations

import functools
import getpass
import os

import mlflow
from dotenv import load_dotenv

EXPERIMENT_NAME = "hayabusa-mcp"

_MAX_TAG_LEN = 250


def configure() -> None:
    """Point MLflow at the configured tracking store and experiment."""
    load_dotenv()
    tracking_uri = os.environ.get("MLFLOW_TRACKING_URI", "./mlruns")
    mlflow.set_tracking_uri(tracking_uri)
    mlflow.set_experiment(EXPERIMENT_NAME)


def _current_user() -> str:
    return os.environ.get("MLFLOW_TRACKING_USER") or getpass.getuser()


def _safe_end_run() -> None:
    """End the active MLflow run, swallowing any failure.

    MLflow-side failures must never break the wrapped tool: a failing
    end_run() should not raise past this call, and should not mask a
    real result/exception from the wrapped tool.
    """
    try:
        mlflow.end_run()
    except Exception:
        pass


def _log_result_fields(result: dict) -> None:
    for key, value in result.items():
        if key == "error":
            continue
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)):
            mlflow.log_metric(key, value)
        elif isinstance(value, str) and len(value) <= _MAX_TAG_LEN:
            mlflow.set_tag(key, value)


def log_tool_call(func):
    """Decorator: log a call to an MCP tool function as an MLflow run."""

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Self-heal: a previously swallowed end_run() failure can leave a
        # stale run on the active-run stack, which would break start_run()
        # below on every subsequent call. Clear it first if present.
        if mlflow.active_run() is not None:
            _safe_end_run()

        try:
            configure()
            mlflow.start_run(run_name=func.__name__)
            mlflow.set_tag("mlflow.user", _current_user())
            mlflow.set_tag("tool_name", func.__name__)
            for key, value in kwargs.items():
                mlflow.log_param(key, value)
        except Exception:
            # Logging must never block the tool itself.
            if mlflow.active_run() is not None:
                _safe_end_run()
            return func(*args, **kwargs)

        try:
            result = func(*args, **kwargs)
        except Exception:
            try:
                mlflow.set_tag("status", "exception")
            except Exception:
                pass
            _safe_end_run()
            raise

        try:
            if isinstance(result, dict) and "error" in result:
                mlflow.set_tag("status", "error")
                mlflow.set_tag("error", str(result["error"])[:_MAX_TAG_LEN])
            else:
                mlflow.set_tag("status", "success")
            if isinstance(result, dict):
                _log_result_fields(result)
        except Exception:
            pass
        finally:
            _safe_end_run()

        return result

    return wrapper
