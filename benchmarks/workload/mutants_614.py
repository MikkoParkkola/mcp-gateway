import sys, math
sys.path.insert(0, "benchmarks/workload")
import eval_workload as ev

def kmax(n, conf=0.95, cap=None):
    best = None
    for k in range(1, n // 2 + 1):
        if 1 - 2 * sum(math.comb(n, i) for i in range(k)) / 2**n >= conf:
            best = k
    if best is not None and cap is not None:
        best = min(best, cap)
    return best

def median(v):
    s = sorted(v); n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2

def make(cap=None, halve=True, centre=median):
    def median_interval(v):
        n = len(v); k = kmax(n, cap=cap)
        if k is None: return None
        s = sorted(v); return (s[k - 1], s[n - k])
    def rel_half_width(v):
        iv = median_interval(v)
        if iv is None: return float("inf")
        c = centre(v)
        if c <= 0: return float("inf")
        w = (iv[1] - iv[0]) / 2 if halve else (iv[1] - iv[0])
        return w / c
    def interval_insufficient(n):
        return kmax(n, cap=cap) is None
    return median_interval, rel_half_width, interval_insufficient

MUTANTS = {
    "CORRECT":       make(),
    "capped-k-at-3": make(cap=3),
    "dropped-/2":    make(halve=False),
    "mean-centre":   make(centre=lambda v: sum(v) / len(v)),
}
PURE = ["test_coverage_calibration", "test_exact_interval_values",
        "test_observed_k_plateau_sawtooth", "test_resolving_power",
        "test_insufficiency_floor", "test_degenerate_input"]

ev.CONF = 0.95
for label, (mi, rhw, ins) in MUTANTS.items():
    ev.median_interval, ev.rel_half_width, ev.interval_insufficient = mi, rhw, ins
    for m in list(sys.modules):
        if m == "test_eval_workload": del sys.modules[m]
    import test_eval_workload as t
    killed = []
    for n in PURE:
        try:
            getattr(t, n)(); 
        except Exception as e:
            killed.append(f"{n} [{str(e)[:70]}]")
    verdict = "KILLED by " + "; ".join(killed) if killed else "*** SURVIVED ALL ***"
    print(f"{label:16} {verdict}\n")
