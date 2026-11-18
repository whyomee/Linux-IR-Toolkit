"""Collector registry.

Collectors are registered in execution order.  The order matters: the IOC
analyser consumes the data produced by the collectors that precede it, and the
network collector benefits from the process inventory when attributing sockets.
"""

from __future__ import annotations

from irkit.collectors.base import BaseCollector
from irkit.collectors.filesystem import FilesystemCollector
from irkit.collectors.ioc import IOCCollector
from irkit.collectors.logs import LogCollector
from irkit.collectors.network import NetworkCollector
from irkit.collectors.persistence import PersistenceCollector
from irkit.collectors.processes import ProcessCollector
from irkit.collectors.ssh import SSHCollector
from irkit.collectors.system import SystemCollector
from irkit.collectors.users import UserCollector

#: Execution order for a full investigation.
COLLECTOR_ORDER: tuple[str, ...] = (
    "system",
    "users",
    "processes",
    "network",
    "ssh",
    "persistence",
    "filesystem",
    "logs",
    "ioc",
)

COLLECTORS: dict[str, type[BaseCollector]] = {
    "system": SystemCollector,
    "users": UserCollector,
    "processes": ProcessCollector,
    "network": NetworkCollector,
    "ssh": SSHCollector,
    "persistence": PersistenceCollector,
    "filesystem": FilesystemCollector,
    "logs": LogCollector,
    "ioc": IOCCollector,
}

#: The IOC analyser is only meaningful after the evidence-producing collectors.
COLLECTOR_PREREQUISITES: dict[str, tuple[str, ...]] = {
    "ioc": tuple(name for name in COLLECTOR_ORDER if name != "ioc"),
}


def get_collector(name: str) -> type[BaseCollector]:
    """Return a collector class by name, raising a helpful error for typos."""
    try:
        return COLLECTORS[name]
    except KeyError as exc:
        available = ", ".join(COLLECTOR_ORDER)
        raise KeyError(f"unknown collector {name!r}; available collectors: {available}") from exc


def expand_names(names: list[str] | tuple[str, ...] | None) -> list[str]:
    """Validate and expand a requested collector list.

    ``None`` means "all collectors".  Requesting ``ioc`` implicitly includes
    its prerequisites so correlation always has evidence to search.
    """
    if names is None:
        return list(COLLECTOR_ORDER)
    requested: list[str] = []
    for raw in names:
        for token in str(raw).split(","):
            name = token.strip().lower()
            if not name:
                continue
            get_collector(name)
            if name not in requested:
                requested.append(name)
    if not requested:
        return list(COLLECTOR_ORDER)
    expanded = list(requested)
    for name in requested:
        for prerequisite in COLLECTOR_PREREQUISITES.get(name, ()):
            if prerequisite not in expanded:
                expanded.insert(expanded.index(name), prerequisite)
    return [name for name in COLLECTOR_ORDER if name in expanded]


__all__ = [
    "COLLECTORS",
    "COLLECTOR_ORDER",
    "COLLECTOR_PREREQUISITES",
    "expand_names",
    "get_collector",
]
