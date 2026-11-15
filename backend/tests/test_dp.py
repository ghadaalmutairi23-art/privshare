import numpy as np
import pytest

from backend import dp


def test_avg_gpa_accuracy_target():
    """Objective 2: average GPA within +-0.2 at epsilon = 0.5 for groups of 100 (4-point scale)."""
    rng = np.random.default_rng(0)
    gpas = list(rng.uniform(2.0, 4.0, 100))
    true_mean = float(np.mean(gpas))
    errors = np.array([abs(dp.noisy_mean(gpas, 0.5, 0.0, 4.0) - true_mean) for _ in range(1000)])
    # Laplace scale b = 4 / (100 * 0.5) = 0.08 -> mean |error| = 0.08, P(|error| <= 0.2) = 1 - e^-2.5 = 0.918
    assert errors.mean() < 0.1
    assert (errors <= 0.2).mean() > 0.88


def test_mean_error_shrinks_with_group_size():
    gpas_small, gpas_large = [3.0] * 20, [3.0] * 400
    err = lambda g: np.mean([abs(dp.noisy_mean(g, 0.5, 0.0, 4.0) - 3.0) for _ in range(300)])  # noqa: E731
    assert err(gpas_large) < err(gpas_small)


def test_mean_stays_in_bounds_and_clamps_inputs():
    for _ in range(200):
        assert 0.0 <= dp.noisy_mean([0.1] * 10, 0.1, 0.0, 4.0) <= 4.0
    # An out-of-range value is clamped before averaging, so it can't dominate the result
    outlier = [3.0] * 99 + [1000.0]
    assert abs(np.mean([dp.noisy_mean(outlier, 1.0, 0.0, 4.0) for _ in range(200)]) - 3.01) < 0.05


def test_count_is_noisy_but_close():
    results = [dp.noisy_count(120, 0.5) for _ in range(500)]
    assert all(isinstance(r, int) and r >= 0 for r in results)
    assert len(set(results)) > 1                     # noise is actually added
    assert abs(np.mean(results) - 120) < 1.0         # unbiased
    assert np.mean([abs(r - 120) for r in results]) < 3.0  # E|noise| = 1/eps = 2


def test_count_never_negative():
    assert all(dp.noisy_count(0, 0.1) >= 0 for _ in range(200))


@pytest.mark.parametrize("bad", [0, -0.5])
def test_invalid_epsilon(bad):
    with pytest.raises(ValueError):
        dp.noisy_count(10, bad)
    with pytest.raises(ValueError):
        dp.noisy_mean([1.0] * 10, bad, 0, 4)


def test_empty_group_refused():
    with pytest.raises(ValueError):
        dp.noisy_mean([], 0.5, 0, 4)
