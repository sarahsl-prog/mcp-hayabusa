import inspect
import sys
from pathlib import Path

import mlflow
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import mlflow_logging
import server


@pytest.fixture
def tracking_dir(tmp_path, monkeypatch):
    uri = f"file://{tmp_path}/mlruns"
    monkeypatch.setenv("MLFLOW_TRACKING_URI", uri)
    monkeypatch.delenv("MLFLOW_TRACKING_USER", raising=False)
    mlflow_logging.configure()
    yield tmp_path
    mlflow.set_tracking_uri(None)


TOOL_FUNCS = [
    (server.scan_evtx, {"file_path": "/nonexistent/x.evtx"}),
    (server.get_hayabusa_rules, {"keyword": "mimikatz"}),
    (server.analyze_coverage, {"identifier": "T1078"}),
    (server.suggest_rule, {"technique_id": "T1078"}),
]


@pytest.mark.parametrize("func,kwargs", TOOL_FUNCS, ids=[f.__name__ for f, _ in TOOL_FUNCS])
def test_tool_logs_a_run(tracking_dir, func, kwargs):
    result = func(**kwargs)

    assert isinstance(result, dict)
    client = mlflow.MlflowClient()
    exp = client.get_experiment_by_name(mlflow_logging_experiment_name())
    runs = client.search_runs([exp.experiment_id])
    assert any(r.data.tags.get("tool_name") == func.__name__ for r in runs)


def mlflow_logging_experiment_name():
    import mlflow_logging

    return mlflow_logging.EXPERIMENT_NAME


@pytest.mark.parametrize("func,_", TOOL_FUNCS, ids=[f.__name__ for f, _ in TOOL_FUNCS])
def test_tool_signature_unchanged_for_fastmcp_introspection(func, _):
    sig = inspect.signature(func)
    assert list(sig.parameters) == list(server._ORIGINAL_SIGNATURES[func.__name__])
