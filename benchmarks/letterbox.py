"""Square letterbox for fixed-input-size face detectors.

Convention: scale the longer side to `target`, center the short side with
zero padding on a square canvas. `letterbox_params` returns
(scale_x, scale_y, pad_x, pad_y) and `restore_boxes` undoes both scale and
padding, clipping to the original frame bounds. `letterbox_image` is the
only consumer of cv2/numpy; the math helpers stay dependency free so the
letterbox unit tests run without OpenCV installed.
"""


def letterbox_params(
    orig_w: int, orig_h: int, target: int
) -> tuple[float, float, int, int]:
    scale = target / max(orig_w, orig_h)
    new_w = int(round(orig_w * scale))
    new_h = int(round(orig_h * scale))
    pad_x = (target - new_w) // 2
    pad_y = (target - new_h) // 2
    return scale, scale, pad_x, pad_y


def letterbox_image(img: "np.ndarray", target: int) -> tuple["np.ndarray", tuple]:
    import cv2
    import numpy as np

    h, w = img.shape[:2]
    sx, sy, pad_x, pad_y = letterbox_params(w, h, target)
    new_w = int(round(w * sx))
    new_h = int(round(h * sy))
    resized = cv2.resize(img, (new_w, new_h), interpolation=cv2.INTER_LINEAR)
    canvas = np.zeros((target, target, 3), dtype=resized.dtype)
    canvas[pad_y : pad_y + new_h, pad_x : pad_x + new_w] = resized
    return canvas, (sx, sy, pad_x, pad_y)


def restore_boxes(
    boxes, params: tuple, orig_w: int, orig_h: int
) -> list[list[float]]:
    sx, sy, pad_x, pad_y = params
    max_x = float(orig_w)
    max_y = float(orig_h)
    out = []
    for b in boxes:
        x1 = (float(b[0]) - pad_x) / sx
        y1 = (float(b[1]) - pad_y) / sy
        x2 = (float(b[2]) - pad_x) / sx
        y2 = (float(b[3]) - pad_y) / sy
        x1 = min(max(x1, 0.0), max_x)
        x2 = min(max(x2, 0.0), max_x)
        y1 = min(max(y1, 0.0), max_y)
        y2 = min(max(y2, 0.0), max_y)
        out.append([x1, y1, x2, y2])
    return out
