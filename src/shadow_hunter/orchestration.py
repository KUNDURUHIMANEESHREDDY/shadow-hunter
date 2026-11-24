"""Reusable, bounded dependency ledger for server-approved capabilities.

This layer tracks dependencies, not permissions. Each capability still needs
its own authenticated gateway invocation and verified result.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DependencyLedger:
    dependencies: dict[str, frozenset[str]]
    _verified: set[str] = field(default_factory=set, init=False)

    @classmethod
    def compile(cls, nodes: list[dict], *, allowed: frozenset[str],
                max_nodes: int = 32) -> DependencyLedger:
        if not isinstance(nodes, list) or len(nodes) > max_nodes:
            raise ValueError("Invalid workflow size")
        graph = {}
        for node in nodes:
            if not isinstance(node, dict) or set(node) != {"id", "depends_on"}:
                raise ValueError("Invalid workflow node")
            name, deps = node["id"], node["depends_on"]
            if (not isinstance(name, str) or name not in allowed or name in graph
                    or not isinstance(deps, list)
                    or any(not isinstance(dep, str) for dep in deps)
                    or len(set(deps)) != len(deps)):
                raise ValueError("Invalid workflow capability or dependency")
            graph[name] = frozenset(deps)
        if any(not deps.issubset(graph) for deps in graph.values()):
            raise ValueError("Unknown workflow dependency")
        # Validate acyclicity before any invocation.
        visited = set()
        while len(visited) < len(graph):
            ready = {name for name, deps in graph.items()
                     if name not in visited and deps.issubset(visited)}
            if not ready:
                raise ValueError("Cyclic workflow dependency")
            visited.update(ready)
        return cls(graph)

    def ready(self) -> tuple[str, ...]:
        return tuple(name for name, deps in self.dependencies.items()
                     if name not in self._verified and deps.issubset(self._verified))

    def mark_verified(self, capability: str) -> None:
        if capability not in self.ready():
            raise ValueError("Unverified workflow dependency or duplicate result")
        self._verified.add(capability)
