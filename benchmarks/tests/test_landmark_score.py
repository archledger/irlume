import math

import pytest

from landmark_score import (
    ANCHOR_MESH_IDX,
    iou,
    mesh_eye_centers,
    mesh_plausible,
    nme,
    point_bounds,
)

MESH_N_IRIS = 478


def _flat_mesh():
    """478 well-separated deterministic points (i, -i) so any leaked index
    shows up as a wrong-but-finite coordinate."""
    return [(float(i), -float(i), 0.0) for i in range(MESH_N_IRIS)]


def _with_iris(mesh, left, right):
    out = [tuple(p) for p in mesh]
    for k, pt in enumerate(left):
        out[468 + k] = (pt[0], pt[1], 0.0)
    for k, pt in enumerate(right):
        out[473 + k] = (pt[0], pt[1], 0.0)
    return out


class TestAnchorIndices:
    def test_eight_distinct_in_range(self):
        assert len(ANCHOR_MESH_IDX) == 8
        assert len(set(ANCHOR_MESH_IDX)) == 8
        for i in ANCHOR_MESH_IDX:
            assert 0 <= i < MESH_N_IRIS


class TestMeshEyeCenters:
    def test_iris_centers_are_block_means(self):
        left = [(10.0 + k, 20.0 - k) for k in range(5)]
        right = [(30.0 + k, 40.0 + k) for k in range(5)]
        mesh = _with_iris(_flat_mesh(), left, right)
        (lx, ly), (rx, ry) = mesh_eye_centers(mesh)
        assert math.isclose(lx, 12.0)
        assert math.isclose(ly, 18.0)
        assert math.isclose(rx, 32.0)
        assert math.isclose(ry, 42.0)

    def test_degenerate_iris_falls_back_to_corner_midpoints(self):
        mesh = _with_iris(_flat_mesh(), [(0.0, 0.0)] * 5, [(0.0, 0.0)] * 5)
        (lx, ly), (rx, ry) = mesh_eye_centers(mesh)
        p33 = mesh[33]
        p133 = mesh[133]
        p362 = mesh[362]
        p263 = mesh[263]
        assert math.isclose(lx, (p33[0] + p133[0]) / 2)
        assert math.isclose(ly, (p33[1] + p133[1]) / 2)
        assert math.isclose(rx, (p362[0] + p263[0]) / 2)
        assert math.isclose(ry, (p362[1] + p263[1]) / 2)

    def test_non_finite_iris_falls_back(self):
        nan = float("nan")
        mesh = _with_iris(_flat_mesh(), [(nan, 1.0)] * 5, [(5.0, 5.0)] * 5)
        (lx, ly), _ = mesh_eye_centers(mesh)
        p33 = mesh[33]
        p133 = mesh[133]
        assert math.isclose(lx, (p33[0] + p133[0]) / 2)
        assert math.isclose(ly, (p33[1] + p133[1]) / 2)

    def test_short_mesh_raises(self):
        with pytest.raises(ValueError):
            mesh_eye_centers([(0.0, 0.0, 0.0)] * 477)


class TestNme:
    def setup_method(self):
        self.gt_a = (10.0, 50.0)
        self.gt_b = (60.0, 50.0)
        self.iod = 50.0

    def test_identical_points_zero(self):
        anchors = [(1.0, 2.0), (3.0, 4.0), (5.0, 6.0)]
        got = nme(
            (self.gt_a, self.gt_b),
            self.gt_a,
            self.gt_b,
            anchors,
            anchors,
        )
        assert got == 0.0

    def test_eye_offset_known_ratio(self):
        shift = 0.1 * self.iod
        pred_a = (self.gt_a[0], self.gt_a[1] + shift)
        pred_b = (self.gt_b[0], self.gt_b[1] + shift)
        got = nme((pred_a, pred_b), self.gt_a, self.gt_b, [], [])
        assert math.isclose(got, 0.1)

    def test_anchor_offset_known_ratio(self):
        anchors_gt = [(0.0, 0.0), (10.0, 0.0)]
        anchors_pred = [(0.0, 0.0), (10.0 + 0.2 * self.iod, 0.0)]
        got = nme(None, self.gt_a, self.gt_b, anchors_pred, anchors_gt)
        assert math.isclose(got, 0.1)

    def test_mixed_eye_and_anchor_error_is_mean(self):
        shift = 0.1 * self.iod
        pred_a = (self.gt_a[0], self.gt_a[1] + shift)
        pred_b = (self.gt_b[0], self.gt_b[1] + shift)
        anchors = [(0.0, 0.0)]
        got = nme((pred_a, pred_b), self.gt_a, self.gt_b, anchors, anchors)
        assert math.isclose(got, 0.1 * 2 / 3)

    def test_zero_interocular_raises(self):
        with pytest.raises(ValueError):
            nme(None, (5.0, 5.0), (5.0, 5.0), [], [])


class TestGeomHelpers:
    def test_point_bounds(self):
        pts = [(1.0, 5.0), (3.0, 2.0), (2.0, 9.0)]
        assert point_bounds(pts) == (1.0, 2.0, 3.0, 9.0)

    def test_iou_identical_one(self):
        assert iou((0.0, 0.0, 10.0, 10.0), (0.0, 0.0, 10.0, 10.0)) == 1.0

    def test_iou_disjoint_zero(self):
        assert iou((0.0, 0.0, 1.0, 1.0), (5.0, 5.0, 6.0, 6.0)) == 0.0

    def test_iou_known_overlap(self):
        got = iou((0.0, 0.0, 10.0, 10.0), (0.0, 0.0, 10.0, 5.0))
        assert math.isclose(got, 0.5)


def _spread_points(n=478):
    return [
        (float(i % 100) + 1.0, float((i * 7) % 200) + 1.0)
        for i in range(n)
    ]


class TestMeshPlausible:
    WIN = (0.0, 0.0, 256.0, 256.0)

    def test_nan_at_non_anchor_index_refused(self):
        pts = _spread_points()
        assert mesh_plausible(pts, self.WIN) is True
        idx = 17
        assert idx not in ANCHOR_MESH_IDX
        pts[idx] = (float("nan"), pts[idx][1])
        assert mesh_plausible(pts, self.WIN) is False
