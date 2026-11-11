import numpy as np

from ids.escalation import escalated, repeat_counts, threshold_from


def test_counts_only_same_key_inside_window():
    t = np.array([0, 10, 20, 100, 15, 30])
    key = np.array(["a", "a", "a", "a", "b", "a"])
    demoted = np.array([True, True, True, True, True, False])
    assert repeat_counts(t, key, demoted).tolist() == [1, 2, 3, 1, 1, 0]


def test_flows_sharing_a_start_time_count_each_other():
    t = np.zeros(4)
    assert repeat_counts(t, np.array(["a"] * 4), np.ones(4, dtype=bool)).tolist() == [4, 4, 4, 4]


def test_window_edge_is_inclusive_and_order_free():
    t = np.array([60.0, 0.0, 61.0])
    assert repeat_counts(t, np.array(["a"] * 3), np.ones(3, dtype=bool)).tolist() == [2, 1, 2]


def test_threshold_exceeds_anything_seen_and_respects_floor():
    assert threshold_from(np.array([0, 0])) == 3
    assert threshold_from(np.array([1, 7, 2])) == 8
    assert threshold_from(np.array([], dtype=int)) == 3


def test_escalation_needs_n_repeats():
    t = np.arange(5) * 5.0
    key = np.array(["a"] * 5)
    demoted = np.ones(5, dtype=bool)
    assert escalated(t, key, demoted, 3).tolist() == [False, False, True, True, True]
    assert not escalated(t, key, np.zeros(5, dtype=bool), 1).any()
