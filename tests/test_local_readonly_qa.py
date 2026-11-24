"""Offline regression tests for the local, read-only QA planner."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "run_red_blue_local_readonly.py"
SPEC = importlib.util.spec_from_file_location("local_readonly_qa", SCRIPT)
qa = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qa)


def test_repeated_case_rejected_and_retry_accepts_remaining_case():
    candidates = [SimpleNamespace(scenario_id="other-read"),
                  SimpleNamespace(scenario_id="missing-read")]
    with patch.object(qa, "infer", side_effect=[
        {"case_id": "own-read"}, {"case_id": "other-read"}
    ]) as infer:
        result = qa.Planner().plan(candidates, previous_observations=(), seed=1)
    assert result.scenario_id == "other-read"
    assert infer.call_count == 2
    assert infer.call_args.args[2]["properties"]["case_id"]["enum"] == [
        "other-read", "missing-read"
    ]


def test_repeated_invalid_choice_fails_closed():
    candidates = [SimpleNamespace(scenario_id="missing-read")]
    with patch.object(qa, "infer", return_value={"case_id": "own-read"}) as infer:
        with pytest.raises(ValueError, match="bounded retries"):
            qa.Planner().plan(candidates, previous_observations=(), seed=1)
    assert infer.call_count == 2
