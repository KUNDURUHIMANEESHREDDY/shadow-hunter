import pytest
from shadow_hunter.orchestration import DependencyLedger


def test_independent_nodes_and_join():
    graph = DependencyLedger.compile([
        {"id": "read_a", "depends_on": []},
        {"id": "read_b", "depends_on": []},
        {"id": "join", "depends_on": ["read_a", "read_b"]},
    ], allowed=frozenset({"read_a", "read_b", "join"}))
    assert graph.ready() == ("read_a", "read_b")
    with pytest.raises(ValueError):
        graph.mark_verified("join")
    graph.mark_verified("read_b")
    assert graph.ready() == ("read_a",)
    graph.mark_verified("read_a")
    assert graph.ready() == ("join",)
    graph.mark_verified("join")
    assert graph.ready() == ()


@pytest.mark.parametrize("nodes", [
    [{"id": "a", "depends_on": ["b"]}],
    [{"id": "a", "depends_on": ["b"]}, {"id": "b", "depends_on": ["a"]}],
    [{"id": "a", "depends_on": []}, {"id": "a", "depends_on": []}],
    [{"id": "write", "depends_on": []}],
])
def test_invalid_graph_fails_closed(nodes):
    with pytest.raises(ValueError):
        DependencyLedger.compile(nodes, allowed=frozenset({"a", "b"}))
