from types import SimpleNamespace

import agent


def proc(pid, name, cpu):
    info = {"pid": pid, "name": name, "cpu_percent": cpu, "memory_percent": 1.0, "username": "u"}
    return SimpleNamespace(info=info, ppid=lambda: 1)


def test_idle_process_is_not_listed_as_the_busiest(monkeypatch):
    fake = [proc(0, "System Idle Process", 1178.6), proc(42, "python.exe", 64.0), proc(7, "svchost.exe", 3.0)]
    monkeypatch.setattr(agent.psutil, "process_iter", lambda attrs: iter(fake))
    names = [p["name"] for p in agent.get_procs(limit=5, sort_by="cpu")]
    assert names == ["python.exe", "svchost.exe"]
