# tests/test_mlflow_logging.py
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mlflow
import pytest

import mlflow_logging


@pytest.fixture
def tracking_dir(tmp_path, monkeypatch):
    uri = f"file://{tmp_path}/mlruns"
    monkeypatch.setenv("MLFLOW_TRACKING_URI", uri)
    monkeypatch.delenv("MLFLOW_TRACKING_USER", raising=False)
    mlflow_logging.configure()
    yield tmp_path
    mlflow.set_tracking_uri(None)


def _latest_run():
    client = mlflow.MlflowClient()
    exp = client.get_experiment_by_name("hayabusa-mcp")
    runs = client.search_runs([exp.experiment_id], order_by=["start_time DESC"])
    return runs[0]


def test_logs_params_and_metrics_on_success(tracking_dir):
    @mlflow_logging.log_tool_call
    def scan_evtx(file_path, min_severity=None):
        return {"file": file_path, "finding_count": 3, "returned_count": 3}

    result = scan_evtx(file_path="/tmp/x.evtx", min_severity="high")

    assert result == {"file": "/tmp/x.evtx", "finding_count": 3, "returned_count": 3}
    run = _latest_run()
    assert run.data.params["file_path"] == "/tmp/x.evtx"
    assert run.data.params["min_severity"] == "high"
    assert run.data.metrics["finding_count"] == 3
    assert run.data.metrics["returned_count"] == 3
    assert run.data.tags["tool_name"] == "scan_evtx"
    assert run.data.tags["status"] == "success"


def test_tags_error_status_on_error_result(tracking_dir):
    @mlflow_logging.log_tool_call
    def get_hayabusa_rules(keyword=None):
        return {"error": "rules dir not found"}

    result = get_hayabusa_rules(keyword="mimikatz")

    assert result == {"error": "rules dir not found"}
    run = _latest_run()
    assert run.data.tags["status"] == "error"
    assert run.data.tags["error"] == "rules dir not found"


def test_reraises_and_still_closes_run_on_exception(tracking_dir):
    @mlflow_logging.log_tool_call
    def broken(x):
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        broken(x=1)

    run = _latest_run()
    assert run.data.tags["status"] == "exception"
    assert mlflow.active_run() is None


def test_user_tag_from_env(tracking_dir, monkeypatch):
    monkeypatch.setenv("MLFLOW_TRACKING_USER", "sarahsl-prog")

    @mlflow_logging.log_tool_call
    def analyze_coverage(identifier):
        return {"identifier": identifier}

    analyze_coverage(identifier="T1078")

    run = _latest_run()
    assert run.data.tags["mlflow.user"] == "sarahsl-prog"


def test_success_returns_result_even_if_mlflow_logging_fails(tracking_dir, monkeypatch):
    """Finding 1: Logging failures after func() succeeds must not break the tool."""

    def raise_fn(*args, **kwargs):
        raise RuntimeError("MLflow disk full")

    monkeypatch.setattr(mlflow, "log_metric", raise_fn)

    @mlflow_logging.log_tool_call
    def suggest_rule(technique_id):
        return {"suggestion": "try this rule"}

    # Even though mlflow.log_metric() fails, the tool should still return its result
    result = suggest_rule(technique_id="T1078")
    assert result == {"suggestion": "try this rule"}
    # Run should still be closed
    assert mlflow.active_run() is None


def test_original_exception_reraised_even_if_mlflow_also_fails(tracking_dir, monkeypatch):
    """Finding 2: Original exception must be re-raised even if mlflow.set_tag() fails."""

    call_count = [0]

    def raise_on_second_call(*args, **kwargs):
        call_count[0] += 1
        if call_count[0] >= 2:
            raise RuntimeError("MLflow connection lost")
        # First call (for tool_name tag) succeeds
        return None

    monkeypatch.setattr(mlflow, "set_tag", raise_on_second_call)

    @mlflow_logging.log_tool_call
    def broken_tool(x):
        raise ValueError("original error from tool")

    # The original ValueError should be re-raised, not the MLflow RuntimeError
    with pytest.raises(ValueError, match="original error from tool"):
        broken_tool(x=1)

    # Run should be closed even though mlflow.set_tag() failed
    assert mlflow.active_run() is None


def test_success_returns_result_even_if_end_run_fails(tracking_dir, monkeypatch):
    """Final review finding 1: a failing end_run() on the success path must not
    propagate and must not prevent the tool's real result from being returned."""

    def raise_fn(*args, **kwargs):
        raise RuntimeError("MLflow end_run failed")

    monkeypatch.setattr(mlflow, "end_run", raise_fn)

    @mlflow_logging.log_tool_call
    def suggest_rule(technique_id):
        return {"suggestion": "try this rule"}

    result = suggest_rule(technique_id="T1078")
    assert result == {"suggestion": "try this rule"}


def test_original_exception_reraised_even_if_end_run_fails(tracking_dir, monkeypatch):
    """Final review finding 1: a failing end_run() on the exception path must not
    mask the wrapped function's original exception."""

    def raise_fn(*args, **kwargs):
        raise RuntimeError("MLflow end_run failed")

    monkeypatch.setattr(mlflow, "end_run", raise_fn)

    @mlflow_logging.log_tool_call
    def broken_tool(x):
        raise ValueError("original tool error")

    with pytest.raises(ValueError, match="original tool error"):
        broken_tool(x=1)


def test_self_heals_stale_active_run_after_end_run_failures_stop(tracking_dir, monkeypatch):
    """Finding 2: a swallowed end_run() failure must not permanently poison the
    active-run stack for subsequent calls once end_run() starts working again."""

    real_end_run = mlflow.end_run
    fail_end_run = [True]

    def maybe_raise_fn(*args, **kwargs):
        if fail_end_run[0]:
            raise RuntimeError("MLflow end_run failed")
        return real_end_run(*args, **kwargs)

    monkeypatch.setattr(mlflow, "end_run", maybe_raise_fn)

    @mlflow_logging.log_tool_call
    def suggest_rule(technique_id):
        return {"suggestion": "try this rule"}

    # First call: end_run() fails and is swallowed, leaving a stale active run.
    result1 = suggest_rule(technique_id="T1078")
    assert result1 == {"suggestion": "try this rule"}
    assert mlflow.active_run() is not None

    # end_run() recovers, but without self-healing the stale run from the
    # previous call would still be sitting on the active-run stack.
    fail_end_run[0] = False

    result2 = suggest_rule(technique_id="T1079")
    assert result2 == {"suggestion": "try this rule"}
    assert mlflow.active_run() is None
