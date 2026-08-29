"""Verification metrics for face recognition benchmarks.

Conventions (Tasks 3-5 consume these exactly):
- Scores are cosine similarities in [-1, 1]; genuine and impostor are
  separate score lists over the pooled evaluation pairs.
- FAR operating points use the impostor quantile: the threshold is the
  k-th largest impostor score with k = floor(far * n) + 1, so the
  realized impostor fraction strictly above the threshold is <= far.
- TAR counts genuine scores strictly above the threshold.
- Fold accuracy scores a pair positive when score > threshold (label 1
  means genuine); a score equal to the threshold counts as negative.
- ten_fold reports each fold's accuracy at that fold's optimal
  threshold (the threshold maximizing the fold's accuracy; ties go to
  the lowest threshold) plus the mean and population sd (ddof 0).
"""

import math


def _far_threshold(scores_impostor: list[float], far: float) -> float:
    if not scores_impostor:
        raise ValueError("impostor scores must be non-empty")
    if not 0.0 <= far <= 1.0:
        raise ValueError(f"far must be in [0, 1], got {far}")
    desc = sorted(scores_impostor, reverse=True)
    k = math.floor(far * len(desc)) + 1
    if k > len(desc):
        return desc[-1] - 1.0
    return desc[k - 1]


def eer(scores_genuine: list[float], scores_impostor: list[float]) -> float:
    """Equal error rate over the pooled similarity distributions."""
    if not scores_genuine or not scores_impostor:
        raise ValueError("eer requires non-empty genuine and impostor scores")
    union = sorted(set(scores_genuine) | set(scores_impostor))
    candidates = [union[0] - 1.0]
    candidates.extend((a + b) / 2.0 for a, b in zip(union, union[1:]))
    candidates.append(union[-1] + 1.0)
    n_gen = len(scores_genuine)
    n_imp = len(scores_impostor)
    best_gap: float | None = None
    best_eer = 0.0
    for t in candidates:
        far = sum(1 for s in scores_impostor if s >= t) / n_imp
        frr = sum(1 for s in scores_genuine if s < t) / n_gen
        gap = abs(far - frr)
        if best_gap is None or gap < best_gap:
            best_gap = gap
            best_eer = (far + frr) / 2.0
    return best_eer


def tar_at_far(
    scores_genuine: list[float], scores_impostor: list[float], far: float
) -> float:
    """Genuine fraction strictly above the impostor quantile at far."""
    if not scores_genuine:
        raise ValueError("genuine scores must be non-empty")
    threshold = _far_threshold(scores_impostor, far)
    above = sum(1 for s in scores_genuine if s > threshold)
    return above / len(scores_genuine)


def far_threshold_table(
    scores_genuine: list[float],
    scores_impostor: list[float],
    fars: list[float],
) -> list[dict]:
    """Rows {"far": f, "threshold": t, "tar": v} for each requested far."""
    if not scores_genuine:
        raise ValueError("genuine scores must be non-empty")
    rows = []
    for f in fars:
        t = _far_threshold(scores_impostor, f)
        tar = sum(1 for s in scores_genuine if s > t) / len(scores_genuine)
        rows.append({"far": f, "threshold": t, "tar": tar})
    return rows


def fold_accuracy(pairs: list[tuple[float, int]], threshold: float) -> float:
    """Accuracy of score > threshold against labels (1 = genuine)."""
    if not pairs:
        raise ValueError("pairs must be non-empty")
    correct = sum(
        1 for score, label in pairs if (score > threshold) == (label == 1)
    )
    return correct / len(pairs)


def ten_fold(
    scores: list[float], labels: list[int], folds: list[int]
) -> dict:
    """Per-fold accuracy at the per-fold optimal threshold, mean and sd."""
    if not (len(scores) == len(labels) == len(folds)):
        raise ValueError("scores, labels and folds must have equal length")
    if not scores:
        raise ValueError("scores must be non-empty")
    by_fold: dict[int, list[tuple[float, int]]] = {}
    for score, label, fold in zip(scores, labels, folds):
        by_fold.setdefault(fold, []).append((score, label))
    per_fold = []
    for fold in sorted(by_fold):
        pairs = by_fold[fold]
        candidates = sorted({score for score, _ in pairs})
        best_acc = fold_accuracy(pairs, candidates[0] - 1.0)
        for t in candidates:
            acc = fold_accuracy(pairs, t)
            if acc > best_acc:
                best_acc = acc
        per_fold.append(best_acc)
    n = len(per_fold)
    mean = sum(per_fold) / n
    var = sum((v - mean) ** 2 for v in per_fold) / n
    return {"acc10fold": mean, "sd": math.sqrt(var), "per_fold": per_fold}
