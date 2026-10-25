from ids.data import BENIGN, LABEL_COL, clean, temporal_split
from ids.synthetic import make_flows
from scripts.multi_env_eval import few_shot


def test_few_shot_takes_k_per_attack_class_from_the_earliest_period_only():
    df = clean(make_flows(120))
    train, _, test = temporal_split(df)
    shots = few_shot({"train": train}, k=5, benign=20, seed=42)
    counts = shots[LABEL_COL].value_counts()
    assert all(counts[c] == 5 for c in counts.index if c != BENIGN)
    assert counts[BENIGN] == 20
    assert set(shots.index) <= set(train.index) and not set(shots.index) & set(test.index)
