from __future__ import annotations

import gc
import os
import platform
import statistics
import subprocess
import time
import tracemalloc
from contextlib import contextmanager
from dataclasses import dataclass

try:
    import resource
except ImportError:
    resource = None  # Windows

try:
    import psutil
except ImportError:
    psutil = None

from curves.ecc import Point


# ======= ECC GROUP OPERATION COUNTER ============

@dataclass
class ECCOpsCounter:
    add_ops: int = 0
    double_ops: int = 0
    mul_ops: int = 0

    @property
    def total_ops(self) -> int:
        # Chỉ cộng add_ops + double_ops vì mul_ops đã bao gồm các phép cộng/nhân đôi bên trong
        return self.add_ops + self.double_ops


@contextmanager
def track_ecc_ops():
    """Tạm thời đếm số phép cộng điểm, nhân đôi điểm và nhân vô hướng của Point."""
    counter = ECCOpsCounter()
    orig_add, orig_mul = Point.__add__, Point.__mul__

    def counted_add(self, other):
        if not self.is_infinity and not other.is_infinity:
            if self == other:
                counter.double_ops += 1
            else:
                counter.add_ops += 1
        return orig_add(self, other)

    def counted_mul(self, n):
        counter.mul_ops += 1
        return orig_mul(self, n)

    Point.__add__, Point.__mul__ = counted_add, counted_mul
    try:
        yield counter
    finally:
        Point.__add__, Point.__mul__ = orig_add, orig_mul


# ======= HARDWARE & MEMORY METRICS ============

def get_cpu_freq_ghz() -> float:
    """Lấy xung nhịp CPU (GHz) để quy đổi cpu_time_ns -> cycles nếu chưa dùng RDTSC."""
    if psutil is not None:
        freq = psutil.cpu_freq()
        if freq and freq.current > 0:
            return freq.current / 1000.0
    try:
        if platform.system() == "Linux":
            with open("/proc/cpuinfo", encoding="utf-8") as f:
                for line in f:
                    if "cpu MHz" in line:
                        return float(line.split(":")[1].strip()) / 1000.0
        elif platform.system() == "Windows":
            out = subprocess.check_output(["wmic", "cpu", "get", "MaxClockSpeed"], text=True)
            mhz = [int(s) for s in out.split() if s.isdigit()]
            if mhz:
                return mhz[0] / 1000.0
    except Exception:
        pass
    return 2.5


CPU_GHZ = get_cpu_freq_ghz()


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

    med_cpu_ns = int(statistics.median(cpus))
    return {
        "wall_time_ns": int(statistics.median(walls)),
        "cpu_time_ns": med_cpu_ns,
        "cpu_cycles": int(med_cpu_ns * CPU_GHZ),
        "cycles_source": "estimated_freq",
        "memory_peak_kib": py_peak_kib,       # Python-managed heap allocations during fn()
        "rss_peak_kib": rss_peak_kib,         # Total OS process peak RAM (includes C/NumPy/etc.)
        "repeats": len(walls),
        "result": result,
    }


if __name__ == "__main__":
    out = measure(lambda: sum(range(10_000)), repeat=5, memory=True)
    assert out["wall_time_ns"] > 0 and out["cpu_time_ns"] >= 0
    assert out["cpu_cycles"] is not None and out["memory_peak_kib"] is not None
    print(f"CPU ≈ {CPU_GHZ:.2f} GHz -> {out}")