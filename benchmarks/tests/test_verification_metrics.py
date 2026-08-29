import pytest

from verification_metrics import (
    eer,
    far_threshold_table,
    fold_accuracy,
    tar_at_far,
    ten_fold,
)


def test_eer_separable_distributions_is_zero():
    assert eer([0.8, 0.9, 0.95], [0.1, 0.2, 0.3]) == 0.0


def test_eer_identical_distributions_is_half():
    scores = [0.1 * i for i in range(1, 11)]
    assert eer(scores, list(scores)) == pytest.approx(0.5)


def test_eer_rejects_empty_inputs():
    with pytest.raises(ValueError):
        eer([], [0.1])
    with pytest.raises(ValueError):
        eer([0.1], [])


def test_tar_at_far_exact_quantile():
    genuine = [0.2, 0.35, 0.5, 0.9]
    impostor = [0.1, 0.2, 0.3, 0.4]
    assert tar_at_far(genuine, impostor, 0.25) == pytest.approx(0.75)
    assert tar_at_far(genuine, impostor, 0.0) == pytest.approx(0.5)
    assert tar_at_far(genuine, impostor, 0.5) == pytest.approx(0.75)
    assert tar_at_far(genuine, impostor, 1.0) == pytest.approx(1.0)


def test_tar_at_far_rejects_out_of_range_far():
    with pytest.raises(ValueError):
        tar_at_far([0.5], [0.1], -0.1)
    with pytest.raises(ValueError):
        tar_at_far([0.5], [0.1], 1.5)


def test_far_threshold_table_rows():
    genuine = [0.2, 0.35, 0.5, 0.9]
    impostor = [0.1, 0.2, 0.3, 0.4]
    rows = far_threshold_table(genuine, impostor, [0.0, 0.25, 1.0])
    assert [r["far"] for r in rows] == [0.0, 0.25, 1.0]
    assert rows[0]["threshold"] == pytest.approx(0.4)
    assert rows[0]["tar"] == pytest.approx(0.5)
    assert rows[1]["threshold"] == pytest.approx(0.3)
    assert rows[1]["tar"] == pytest.approx(0.75)
    assert rows[2]["threshold"] < min(impostor)
    assert rows[2]["tar"] == pytest.approx(1.0)


def test_fold_accuracy_exact_fractions():
    pairs = [(0.9, 1), (0.8, 1), (0.2, 0), (0.3, 1)]
    assert fold_accuracy(pairs, 0.5) == pytest.approx(0.75)
    assert fold_accuracy([(0.5, 1)], 0.5) == pytest.approx(0.0)
    assert fold_accuracy([(0.5, 0)], 0.5) == pytest.approx(1.0)


def test_ten_fold_constructed_two_fold_case():
    scores = [0.9, 0.1, 0.6, 0.2, 0.7]
    labels = [1, 0, 1, 0, 0]
    folds = [0, 0, 1, 1, 1]
    out = ten_fold(scores, labels, folds)
    assert out["per_fold"] == pytest.approx([1.0, 2.0 / 3.0])
    assert out["acc10fold"] == pytest.approx(5.0 / 6.0)
    assert out["sd"] == pytest.approx(1.0 / 6.0)


def test_ten_fold_rejects_mismatched_lengths():
    with pytest.raises(ValueError):
        ten_fold([0.1, 0.2], [1], [0, 0])
    with pytest.raises(ValueError):
        ten_fold([], [], [])
