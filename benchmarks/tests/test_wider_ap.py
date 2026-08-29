import pytest

from wider_ap import (
    evaluate,
    evaluate_image,
    evaluate_tier,
    iou,
    parse_val_gt,
    voc_ap,
)


GT_SNIPPET = """0--Parade/0_Parade_marchingband_1_849.jpg
1
449,330,122,149,0,0,0,0,0,0

0--Parade/0_Parade_Parade_0_452.jpg
2
361,99,60,71,0,0,0,1,0,0
123,456,50,60,0,0,0,0,0,0

0--Parade/0_Parade_marchingband_1_799.jpg
0

"""


def _write_gt(tmp_path):
    p = tmp_path / "wider_face_val_bbx_gt.txt"
    p.write_text(GT_SNIPPET, encoding="utf-8")
    return p


def test_parse_val_gt_structure(tmp_path):
    gt = parse_val_gt(_write_gt(tmp_path))
    assert set(gt) == {
        "0--Parade/0_Parade_marchingband_1_849.jpg",
        "0--Parade/0_Parade_Parade_0_452.jpg",
        "0--Parade/0_Parade_marchingband_1_799.jpg",
    }
    first = gt["0--Parade/0_Parade_marchingband_1_849.jpg"]
    assert len(first) == 1
    assert first[0]["box"] == (449.0, 330.0, 571.0, 479.0)
    assert first[0]["invalid"] is False
    second = gt["0--Parade/0_Parade_Parade_0_452.jpg"]
    assert len(second) == 2
    assert second[0]["box"] == (361.0, 99.0, 421.0, 170.0)
    assert second[0]["invalid"] is True
    assert second[1]["invalid"] is False
    assert gt["0--Parade/0_Parade_marchingband_1_799.jpg"] == []


def test_parse_val_gt_space_separated_lines(tmp_path):
    p = tmp_path / "wider_face_val_bbx_gt.txt"
    p.write_text(
        "0--Parade/0_Parade_marchingband_1_849.jpg\n"
        "1\n"
        "449 330 122 149 0 0 0 0 0 0 \n"
        "\n"
        "0--Parade/0_Parade_Parade_0_452.jpg\n"
        "2\n"
        "361 99 60 71 0 0 0 1 0 0\n"
        "123 456 50 60 0 0 0 0 0 0\n"
        "\n",
        encoding="utf-8",
    )
    gt = parse_val_gt(p)
    first = gt["0--Parade/0_Parade_marchingband_1_849.jpg"]
    assert first[0]["box"] == (449.0, 330.0, 571.0, 479.0)
    assert first[0]["invalid"] is False
    second = gt["0--Parade/0_Parade_Parade_0_452.jpg"]
    assert second[0]["invalid"] is True
    assert second[1]["box"] == (123.0, 456.0, 173.0, 516.0)


def test_iou_identity_overlap_disjoint():
    box = (0.0, 0.0, 10.0, 10.0)
    assert iou(box, box) == 1.0
    half_shift = (5.0, 0.0, 15.0, 10.0)
    assert iou(box, half_shift) == pytest.approx(1.0 / 3.0)
    far = (100.0, 100.0, 110.0, 110.0)
    assert iou(box, far) == 0.0


def test_evaluate_image_perfect_match():
    gt = [
        {"box": (0.0, 0.0, 10.0, 10.0), "invalid": False},
        {"box": (20.0, 20.0, 30.0, 30.0), "invalid": False},
    ]
    preds = [(0.9, [0.0, 0.0, 10.0, 10.0]), (0.8, [20.0, 20.0, 30.0, 30.0])]
    assert evaluate_image(preds, gt) == (2, 0, 2)


def test_evaluate_image_duplicate_detection_is_fp():
    gt = [{"box": (0.0, 0.0, 10.0, 10.0), "invalid": False}]
    preds = [(0.9, [0.0, 0.0, 10.0, 10.0]), (0.8, [0.0, 0.0, 10.0, 10.0])]
    assert evaluate_image(preds, gt) == (1, 1, 1)


def test_evaluate_image_invalid_gt_excluded_from_tp_and_n_gt():
    gt = [
        {"box": (0.0, 0.0, 10.0, 10.0), "invalid": True},
        {"box": (40.0, 40.0, 50.0, 50.0), "invalid": False},
    ]
    preds = [
        (0.9, [0.0, 0.0, 10.0, 10.0]),
        (0.8, [40.0, 40.0, 50.0, 50.0]),
    ]
    assert evaluate_image(preds, gt) == (1, 1, 1)


def test_evaluate_tier_discards_off_tier_predictions():
    gt = {
        "a.jpg": [
            {"box": (0.0, 0.0, 10.0, 60.0), "invalid": False},
            {"box": (100.0, 100.0, 105.0, 104.0), "invalid": False},
        ]
    }
    preds = {
        "a.jpg": [
            (0.9, [0.0, 0.0, 10.0, 60.0]),
            (0.8, [100.0, 100.0, 105.0, 104.0]),
        ]
    }
    out = evaluate_tier(preds, gt, min_h=10.0, strict=False)
    assert out["tp"] == 1
    assert out["fp"] == 0
    assert out["n_gt"] == 1
    assert out["ap"] == pytest.approx(1.0)


def test_evaluate_tier_zero_overlap_pred_stays_fp():
    gt = {
        "a.jpg": [{"box": (0.0, 0.0, 10.0, 60.0), "invalid": False}]
    }
    preds = {
        "a.jpg": [
            (0.9, [0.0, 0.0, 10.0, 60.0]),
            (0.8, [500.0, 500.0, 510.0, 520.0]),
        ]
    }
    out = evaluate_tier(preds, gt, min_h=10.0, strict=False)
    assert out["tp"] == 1
    assert out["fp"] == 1
    assert out["n_gt"] == 1


def test_evaluate_tier_strict_cut_and_invalid_excluded():
    gt = {
        "a.jpg": [
            {"box": (0.0, 0.0, 10.0, 50.0), "invalid": False},
            {"box": (100.0, 100.0, 110.0, 180.0), "invalid": True},
        ]
    }
    preds = {"a.jpg": [(0.9, [0.0, 0.0, 10.0, 50.0])]}
    strict = evaluate_tier(preds, gt, min_h=50.0, strict=True)
    assert strict["n_gt"] == 0
    assert strict["tp"] == 0
    assert strict["fp"] == 0
    loose = evaluate_tier(preds, gt, min_h=50.0, strict=False)
    assert loose["n_gt"] == 1
    assert loose["tp"] == 1


def test_voc_ap_perfect_ranking_is_one():
    assert voc_ap([0.9, 0.8], [1, 1], 2) == pytest.approx(1.0)


def test_voc_ap_reversed_ranking_below_half():
    assert voc_ap([0.9, 0.8, 0.7], [0, 0, 1], 1) < 0.5


def test_voc_ap_all_fp_is_zero():
    assert voc_ap([0.9, 0.8], [0, 0], 2) == 0.0


def test_evaluate_aggregates_across_images():
    gt = {
        "a.jpg": [{"box": (0.0, 0.0, 10.0, 10.0), "invalid": False}],
        "b.jpg": [
            {"box": (0.0, 0.0, 10.0, 10.0), "invalid": False},
            {"box": (50.0, 50.0, 60.0, 60.0), "invalid": False},
        ],
    }
    preds = {
        "a.jpg": [(0.95, [0.0, 0.0, 10.0, 10.0])],
        "b.jpg": [(0.8, [0.0, 0.0, 10.0, 10.0])],
        "c.jpg": [(0.1, [0.0, 0.0, 10.0, 10.0]), (0.9, [100.0, 100.0, 110.0, 110.0])],
    }
    gt["c.jpg"] = [{"box": (0.0, 0.0, 10.0, 10.0), "invalid": False}]
    out = evaluate(preds, gt)
    assert out["tp"] == 3
    assert out["fp"] == 1
    assert out["n_gt"] == 4
    assert out["ap"] == pytest.approx(0.625)
