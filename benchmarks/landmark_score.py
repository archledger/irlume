"""Pure landmark scoring for the calibration landmark bench.

Dependency-free math only (the letterbox.py precedent): every function
accepts plain sequences of (x, y[, z]) points so the unit tests run without
numpy or OpenCV installed.

Conventions:
- Mesh points are the 478-point face_landmarker topology (468 dense points
  plus 10 iris points; iris block indices 468-472 left, 473-477 right).
- ANCHOR_MESH_IDX names the mesh points with an unambiguous counterpart in
  sparse GT schemes (98-pt WFLW, 68-pt 300W): eye corners, mouth corners,
  nose tip, chin. Schemes without separate inner-eye corners (68-pt) drop
  the two inner-corner anchors at the bench layer.
- NME normalizes by the GT inter-ocular distance (distance between the two
  GT eye centers), the standard landmark-error denominator.
"""

import math


MESH_N_IRIS = 478
# Left iris 468-472, right iris 473-477 (face_landmarker iris refinement).
IRIS_LEFT = range(468, 473)
IRIS_RIGHT = range(473, 478)

# Mesh anchors with cross-scheme GT counterparts, in correspondence order:
# 33 left eye outer corner, 133 left eye inner corner, 362 right eye inner
# corner, 263 right eye outer corner, 61 mouth left corner, 291 mouth right
# corner, 1 nose tip, 152 chin.
ANCHOR_MESH_IDX = [33, 133, 362, 263, 61, 291, 1, 152]
# The two inner-corner anchors, dropped for GT schemes that only pin the
# eye outline ends (68-pt): keep [33, 263] outer corners instead.
ANCHOR_MESH_INNER = (133, 362)


def _xy(pt) -> tuple[float, float]:
    return (float(pt[0]), float(pt[1]))


def mesh_eye_centers(
    mesh478,
) -> tuple[tuple[float, float], tuple[float, float]]:
    """Predicted eye centers from the 478-point mesh.

    Primary: iris centers, the mean of the left iris block (468-472) and
    the right iris block (473-477). Fallback when a block is degenerate
    (any non-finite coordinate, or the five points collapsed onto one
    spot): the midpoint of the eye corners (33, 133) for the left eye and
    (362, 263) for the right, the anchors a mesh without iris refinement
    still gets right.

    Raises ValueError when the input carries fewer than 478 points.
    """
    if len(mesh478) < MESH_N_IRIS:
        raise ValueError(
            f"expected {MESH_N_IRIS} mesh points, got {len(mesh478)}"
        )
    centers = []
    for block, corner_a, corner_b in (
        (IRIS_LEFT, 33, 133),
        (IRIS_RIGHT, 362, 263),
    ):
        pts = [mesh478[i] for i in block]
        xs = [float(p[0]) for p in pts]
        ys = [float(p[1]) for p in pts]
        finite = all(math.isfinite(v) for v in xs + ys)
        span = max(max(xs) - min(xs), max(ys) - min(ys)) if finite else 0.0
        if finite and span > 1e-9:
            centers.append((sum(xs) / len(xs), sum(ys) / len(ys)))
        else:
            a = _xy(mesh478[corner_a])
            b = _xy(mesh478[corner_b])
            centers.append(((a[0] + b[0]) / 2, (a[1] + b[1]) / 2))
    return centers[0], centers[1]


def nme(
    pred_pts,
    gt_eye_center_a,
    gt_eye_center_b,
    anchors_pred,
    anchors_gt,
) -> float:
    """Normalized mean error: mean L2 over the correspondences divided by
    the GT inter-ocular distance.

    `pred_pts` is the predicted eye-center pair (as mesh_eye_centers
    returns) scored against `gt_eye_center_a`/`gt_eye_center_b`, or None
    to score anchors only. `anchors_pred`/`anchors_gt` are equal-length
    point lists; the error set is the eye-center pairs followed by the
    anchor pairs, so the eye NME call passes empty anchor lists and the
    anchor NME call passes pred_pts=None. Raises ValueError on an
    anchor-length mismatch or a zero GT inter-ocular distance (a
    degenerate annotation, never a zero error).
    """
    if len(anchors_pred) != len(anchors_gt):
        raise ValueError(
            "anchor length mismatch: "
            f"{len(anchors_pred)} pred vs {len(anchors_gt)} gt"
        )
    iod = math.hypot(
        gt_eye_center_b[0] - gt_eye_center_a[0],
        gt_eye_center_b[1] - gt_eye_center_a[1],
    )
    if iod <= 0.0:
        raise ValueError("zero inter-ocular distance in GT")
    errors = []
    if pred_pts is not None:
        errors.append(
            math.hypot(
                pred_pts[0][0] - gt_eye_center_a[0],
                pred_pts[0][1] - gt_eye_center_a[1],
            )
        )
        errors.append(
            math.hypot(
                pred_pts[1][0] - gt_eye_center_b[0],
                pred_pts[1][1] - gt_eye_center_b[1],
            )
        )
    for pp, gp in zip(anchors_pred, anchors_gt):
        errors.append(math.hypot(pp[0] - gp[0], pp[1] - gp[1]))
    if not errors:
        raise ValueError("no correspondences to score")
    return (sum(errors) / len(errors)) / iod


def point_bounds(points) -> tuple[float, float, float, float]:
    """Tight axis-aligned box (x1, y1, x2, y2) around the points."""
    xs = [float(p[0]) for p in points]
    ys = [float(p[1]) for p in points]
    return (min(xs), min(ys), max(xs), max(ys))


def iou(a, b) -> float:
    """Intersection-over-union of two (x1, y1, x2, y2) boxes."""
    ix1 = max(a[0], b[0])
    iy1 = max(a[1], b[1])
    ix2 = min(a[2], b[2])
    iy2 = min(a[3], b[3])
    iw = max(0.0, ix2 - ix1)
    ih = max(0.0, iy2 - iy1)
    inter = iw * ih
    if inter <= 0.0:
        return 0.0
    area_a = max(0.0, a[2] - a[0]) * max(0.0, a[3] - a[1])
    area_b = max(0.0, b[2] - b[0]) * max(0.0, b[3] - b[1])
    union = area_a + area_b - inter
    if union <= 0.0:
        return 0.0
    return inter / union


def mesh_plausible(pts, win) -> bool:
    """The runtime's mesh_output_plausible gate, ported: EVERY point must
    be finite (a NaN coordinate would otherwise sort past the band check
    and escape into the anchor errors), at least half the points must sit
    inside the sampled window plus a 25% slop margin, and the central 80%
    span must be at least 2px on both axes.

    `win` is the sampled window (x, y, w, h) in original image
    coordinates, as returned by the bench's crop_square.
    """
    x0, y0, w, h = (float(v) for v in win)
    sx, sy = w * 0.25, h * 0.25
    inside = 0
    for p in pts:
        x, y = float(p[0]), float(p[1])
        if not (math.isfinite(x) and math.isfinite(y)):
            return False
        if x0 - sx <= x <= x0 + w + sx and y0 - sy <= y <= y0 + h + sy:
            inside += 1
    if inside * 2 < len(pts):
        return False

    def central_span(vals):
        v = sorted(vals)
        lo = len(v) // 10
        hi = len(v) - 1 - lo
        return v[hi] - v[lo] if hi > lo else 0.0

    return (
        central_span([float(p[0]) for p in pts]) >= 2.0
        and central_span([float(p[1]) for p in pts]) >= 2.0
    )
