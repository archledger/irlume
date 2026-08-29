import pytest

from pad_score import (
    apcer_bpcer,
    median_vote,
    roc_auc,
    species_breakdown,
    vote_video,
)


def test_apcer_bpcer_perfect_separation():
    r = apcer_bpcer([0.9, 0.8], [0.1, 0.2], 0.5)
    assert r == {"apcer": 0.0, "bpcer": 0.0}


def test_apcer_bpcer_known_fractions():
    r = apcer_bpcer([0.4, 0.9, 0.6], [0.2, 0.7], 0.5)
    assert r["apcer"] == pytest.approx(1 / 3)
    assert r["bpcer"] == pytest.approx(1 / 2)


def test_apcer_bpcer_boundary_semantics():
    r = apcer_bpcer([0.5], [0.5], 0.5)
    assert r == {"apcer": 0.0, "bpcer": 1.0}


def test_apcer_bpcer_rejects_empty_inputs():
    with pytest.raises(ValueError):
        apcer_bpcer([], [0.1], 0.5)
    with pytest.raises(ValueError):
        apcer_bpcer([0.9], [], 0.5)


def test_roc_auc_perfect_separation():
    assert roc_auc([0.8, 0.9], [0.1, 0.2]) == pytest.approx(1.0)
    assert roc_auc([0.1, 0.2], [0.8, 0.9]) == pytest.approx(0.0)


def test_roc_auc_tie_handling():
    assert roc_auc([0.5, 0.8], [0.5, 0.2]) == pytest.approx(0.875)


def test_roc_auc_rejects_empty_inputs():
    with pytest.raises(ValueError):
        roc_auc([], [0.1])
    with pytest.raises(ValueError):
        roc_auc([0.9], [])


def test_species_breakdown_rows_sorted_and_exact():
    rows = species_breakdown(
        [("cat", 0.9), ("cat", 0.2), ("dog", 0.6), ("bird", 0.4)], 0.5
    )
    assert rows == [
        {"species": "bird", "n": 1, "caught": 0, "tpr": 0.0},
        {"species": "cat", "n": 2, "caught": 1, "tpr": 0.5},
        {"species": "dog", "n": 1, "caught": 1, "tpr": 1.0},
    ]


def test_species_breakdown_threshold_is_inclusive():
    rows = species_breakdown([("x", 0.5)], 0.5)
    assert rows == [{"species": "x", "n": 1, "caught": 1, "tpr": 1.0}]
    assert species_breakdown([], 0.5) == []


def test_median_vote_known_values():
    assert median_vote([0.1, 0.9, 0.5]) == pytest.approx(0.5)
    assert median_vote([0.1, 0.2, 0.3, 0.9]) == pytest.approx(0.25)
    assert median_vote([0.7]) == pytest.approx(0.7)


def test_vote_video_rolling_median_7_frames():
    frames = [[0.1], [0.9], [0.5], [0.3], [0.7], [0.2], [0.8]]
    assert vote_video(frames) == pytest.approx([0.1, 0.5, 0.5, 0.4, 0.5, 0.5, 0.5])


def test_vote_video_short_windows_use_what_exists():
    assert vote_video([[0.2], [0.8]]) == pytest.approx([0.2, 0.5])
    assert vote_video([]) == []
