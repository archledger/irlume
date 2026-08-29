"""PAD scoring for the calibration campaign.

Score semantics are pinned: s = P(spoof). APCER is the fraction of ATTACK
samples with s < threshold; BPCER is the fraction of GENUINE samples with
s >= threshold. AUC is rank-based (Mann-Whitney) with average ranks for
tied scores. The vote functions emulate the ADR-0013 5-frame median vote:
a video's vote at each time step is the median of the last 5 frames'
scores.
"""

import statistics


def apcer_bpcer(
    scores_attack: list[float],
    scores_genuine: list[float],
    threshold: float,
) -> dict:
    if not scores_attack or not scores_genuine:
        raise ValueError("apcer_bpcer needs at least one attack and one genuine score")
    apcer = sum(1 for s in scores_attack if s < threshold) / len(scores_attack)
    bpcer = sum(1 for s in scores_genuine if s >= threshold) / len(scores_genuine)
    return {"apcer": apcer, "bpcer": bpcer}


def roc_auc(scores_attack: list[float], scores_genuine: list[float]) -> float:
    n_attack = len(scores_attack)
    n_genuine = len(scores_genuine)
    if n_attack == 0 or n_genuine == 0:
        raise ValueError("roc_auc needs at least one attack and one genuine score")
    combined = sorted(scores_attack + scores_genuine)
    avg_ranks: dict[float, float] = {}
    i = 0
    while i < len(combined):
        j = i
        while j + 1 < len(combined) and combined[j + 1] == combined[i]:
            j += 1
        avg_ranks[combined[i]] = (i + j) / 2 + 1
        i = j + 1
    rank_sum_attack = sum(avg_ranks[s] for s in scores_attack)
    u = rank_sum_attack - n_attack * (n_attack + 1) / 2
    return u / (n_attack * n_genuine)


def species_breakdown(
    per_sample: list[tuple[str, float]],
    threshold: float,
) -> list[dict]:
    by_species: dict[str, list[float]] = {}
    for species, s in per_sample:
        by_species.setdefault(species, []).append(s)
    rows = []
    for species in sorted(by_species):
        scores = by_species[species]
        caught = sum(1 for s in scores if s >= threshold)
        rows.append(
            {
                "species": species,
                "n": len(scores),
                "caught": caught,
                "tpr": caught / len(scores),
            }
        )
    return rows


def median_vote(scores: list[float]) -> float:
    return statistics.median(scores)


def vote_video(frames: list[list[float]]) -> list[float]:
    votes = []
    for t in range(len(frames)):
        window = [s for fr in frames[max(0, t - 4) : t + 1] for s in fr]
        votes.append(statistics.median(window))
    return votes
