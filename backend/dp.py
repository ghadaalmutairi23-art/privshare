"""Differential Privacy engine: Laplace mechanism via OpenDP. The only module that imports OpenDP.

Neighbouring datasets (what a single student can change):
- count:      one student added or removed  -> d_in = 1, sensitivity 1
- mean / rate: one student's value changed in a group of n -> d_in = 2 (symmetric distance),
               sensitivity (hi - lo) / n. The group size n is treated as public here;
               it is never returned to the analyst.

Each measurement is built for the requested epsilon and OpenDP's own privacy map is
checked (`map(d_in) <= epsilon`) before any noise is released.
Clamping or rounding the noisy output is post-processing and does not weaken the guarantee.
"""
import opendp.prelude as dp

dp.enable_features("contrib")

COUNT_D_IN = 1
MEAN_D_IN = 2
# Tiny scale increase so floating-point rounding in OpenDP's map stays within epsilon
_SCALE_MARGIN = 1 + 1e-6


def _calibrate(make, ideal_scale: float, d_in: int, epsilon: float):
    """Measurement whose privacy loss is at most epsilon (checked by OpenDP)."""
    meas = make(ideal_scale * _SCALE_MARGIN)
    if meas.map(d_in) > epsilon:
        meas = make(dp.binary_search_param(make, d_in=d_in, d_out=epsilon))
    if meas.map(d_in) > epsilon:  # explicit check (asserts can be disabled with -O)
        raise RuntimeError("could not calibrate noise to the requested epsilon")
    return meas


def _check_epsilon(epsilon: float) -> None:
    if not epsilon > 0:
        raise ValueError("epsilon must be positive")


def noisy_count(true_count: int, epsilon: float) -> int:
    """Count with discrete Laplace noise (scale 1/epsilon), never negative."""
    _check_epsilon(epsilon)

    def make(scale):
        return (dp.t.make_count(dp.vector_domain(dp.atom_domain(T=int)), dp.symmetric_distance())
                >> dp.m.then_laplace(scale))

    meas = _calibrate(make, 1.0 / epsilon, COUNT_D_IN, epsilon)
    return max(0, int(meas([0] * true_count)))


def noisy_mean(values: list[float], epsilon: float, lo: float, hi: float) -> float:
    """Mean of values clamped to [lo, hi] plus Laplace noise; result kept in [lo, hi]."""
    _check_epsilon(epsilon)
    n = len(values)
    if n == 0:
        raise ValueError("empty group")
    if not lo < hi:
        raise ValueError("lo must be below hi")

    def make(scale):
        domain = dp.vector_domain(dp.atom_domain(T=float, nan=False), size=n)
        return (dp.t.make_clamp(domain, dp.symmetric_distance(), bounds=(float(lo), float(hi)))
                >> dp.t.then_mean() >> dp.m.then_laplace(scale))

    meas = _calibrate(make, (hi - lo) / n / epsilon, MEAN_D_IN, epsilon)
    return min(hi, max(lo, float(meas([float(v) for v in values]))))
