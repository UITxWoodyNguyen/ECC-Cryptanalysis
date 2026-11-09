"""Wall/CPU timing harness. Python reports cpu_cycles=None; use the C/RDTSC build for hardware cycles."""
import statistics
import time
import tracemalloc


def measure(fn, *args, repeat=5, warmup=0, memory=False, **kwargs):
    """Run fn and return median wall/cpu ns, optional peak Python heap, and the last result."""
    for _ in range(warmup):
        fn(*args, **kwargs)

    walls, cpus = [], []
    result = None
    for _ in range(max(1, repeat)):
        c0 = time.process_time_ns()
        t0 = time.perf_counter_ns()
        result = fn(*args, **kwargs)
        walls.append(time.perf_counter_ns() - t0)
        cpus.append(time.process_time_ns() - c0)

    peak = None
    if memory:
        tracemalloc.start()
        fn(*args, **kwargs)
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()

    return {
        "wall_time_ns": int(statistics.median(walls)),
        "cpu_time_ns": int(statistics.median(cpus)),
        "cpu_cycles": None,
        "memory_peak_kib": None if peak is None else round(peak / 1024, 1),
        "repeats": len(walls),
        "result": result,
    }


if __name__ == "__main__":
    out = measure(lambda: sum(range(10_000)), repeat=3, memory=True)
    assert out["wall_time_ns"] > 0 and out["cpu_time_ns"] > 0
    assert out["cpu_cycles"] is None and out["memory_peak_kib"] is not None
    print(out)
