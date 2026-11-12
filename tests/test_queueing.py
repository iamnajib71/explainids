import numpy as np

from ids.queueing import completion_times, queue_estimate


def test_analyst_works_first_in_first_out():
    assert completion_times(np.array([0.0, 10.0, 500.0]), 60).tolist() == [60.0, 120.0, 560.0]


def test_quiet_traffic_means_no_wait():
    q = queue_estimate([], 3600)
    assert q["median_seconds"] == 0 and q["worst_seconds"] == 0 and q["keeps_up"]


def test_a_flood_makes_the_attack_wait():
    q = queue_estimate(np.arange(0, 3600, 10), 3600)       # 360 alerts an hour, one reviewed a minute
    assert q["alerts_per_hour"] == 360 and not q["keeps_up"]
    assert q["median_seconds"] > 3600 and q["worst_seconds"] >= q["median_seconds"]


def test_too_short_a_recording_gives_no_estimate():
    assert queue_estimate([1, 2, 3], 30) is None
    assert queue_estimate([1, 2, 3], float("nan")) is None
