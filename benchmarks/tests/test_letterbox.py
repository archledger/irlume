from letterbox import letterbox_params, restore_boxes


def test_letterbox_square_input_scales_long_side():
    sx, sy, pad_x, pad_y = letterbox_params(1280, 960, 640)
    assert sx == 0.5 and sy == 0.5
    assert pad_x == 0 and pad_y > 0


def test_restore_boxes_roundtrip():
    p = letterbox_params(1280, 960, 640)
    boxes = [[10.0, 10.0, 100.0, 100.0]]
    out = restore_boxes(boxes, p, orig_w=1280, orig_h=960)
    assert out[0][0] <= out[0][2] and out[0][1] <= out[0][3]


def test_letterbox_centered_padding_on_short_side():
    sx, sy, pad_x, pad_y = letterbox_params(960, 1280, 640)
    assert sx == 0.5 and sy == 0.5
    assert pad_x > 0 and pad_y == 0
    assert pad_x == (640 - int(round(960 * 0.5))) // 2


def test_letterbox_params_non_divisible_size():
    sx, sy, pad_x, pad_y = letterbox_params(1000, 700, 640)
    assert sx == 0.64 and sy == 0.64
    assert pad_x == 0
    assert pad_y == (640 - int(round(700 * 0.64))) // 2


def test_restore_boxes_clips_to_original_bounds():
    p = letterbox_params(1280, 960, 640)
    out = restore_boxes([[0.0, 0.0, 640.0, 640.0]], p, orig_w=1280, orig_h=960)
    b = out[0]
    assert 0.0 <= b[0] <= b[2] <= 1280.0
    assert 0.0 <= b[1] <= b[3] <= 960.0
