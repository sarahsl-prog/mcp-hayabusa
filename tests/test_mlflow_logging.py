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
