import gc
import os
import platform
import statistics
import time
import tracemalloc

try:
    import resource
except ImportError:
    resource = None  # Windows

try:
    import psutil
except ImportError:
    psutil = None


def _get_peak_rss_kib() -> float | None:
    """Return process peak Resident Set Size (RSS) in KiB across Linux, macOS, and Windows."""
    if resource is not None:
        # Linux reports ru_maxrss in KiB; macOS/BSD reports it in bytes.
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if platform.system() == "Darwin":
            return round(rss / 1024, 1)
        return round(float(rss), 1)

    if psutil is not None:
        mem_info = psutil.Process(os.getpid()).memory_info()
        # peak_wset is available on Windows
        peak_bytes = getattr(mem_info, "peak_wset", mem_info.rss)
        return round(peak_bytes / 1024, 1)

    return None


def measure(fn, *args, repeat=7, warmup=1, memory=False, disable_gc=True, **kwargs):
    """Run fn and return median wall/cpu ns, optional peak memory (Python heap & OS RSS), and the last result."""
    for _ in range(warmup):
        fn(*args, **kwargs)

    walls, cpus = [], []
    result = None

    gc_was_enabled = gc.isenabled()
    if disable_gc and gc_was_enabled:
        gc.disable()

    try:
        for _ in range(max(1, repeat)):
            c0 = time.process_time_ns()
            t0 = time.perf_counter_ns()
            result = fn(*args, **kwargs)
            walls.append(time.perf_counter_ns() - t0)
            cpus.append(time.process_time_ns() - c0)
    finally:
        if disable_gc and gc_was_enabled:
            gc.enable()

    py_peak_kib = None
    rss_peak_kib = None
    if memory:
        tracemalloc.start()
        try:
            fn(*args, **kwargs)
            _, peak = tracemalloc.get_traced_memory()
            py_peak_kib = round(peak / 1024, 1)
            rss_peak_kib = _get_peak_rss_kib()
        finally:
            tracemalloc.stop()

    return {
        "wall_time_ns": int(statistics.median(walls)),
        "cpu_time_ns": int(statistics.median(cpus)),
        "cpu_cycles": None,
        "memory_peak_kib": py_peak_kib,       # Python-managed heap allocations during fn()
        "rss_peak_kib": rss_peak_kib,         # Total OS process peak RAM (includes C/NumPy/etc.)
        "repeats": len(walls),
        "result": result,
    }


if __name__ == "__main__":
    out = measure(lambda: sum(range(10_000)), repeat=5, memory=True)
    assert out["wall_time_ns"] > 0 and out["cpu_time_ns"] >= 0
    assert out["cpu_cycles"] is None and out["memory_peak_kib"] is not None
    print(out)