import pytest

from datasets import DatasetFile, DatasetSpec, get_dataset, list_datasets


def test_wider_face_spec_is_complete():
    spec = get_dataset("wider_face")
    assert spec.source == "hf"
    assert spec.repo == "CUHK-CSE/wider_face"
    paths = {f.path for f in spec.files}
    assert "data/WIDER_train.zip" in paths
    assert "data/WIDER_val.zip" in paths
    assert "data/wider_face_split.zip" in paths
    assert all(f.extract for f in spec.files)
    assert spec.provenance_url.startswith("https://huggingface.co/datasets/")
    assert "research" in spec.license_note.lower()
    assert spec.notes


def test_every_entry_has_required_fields():
    for name in list_datasets():
        spec = get_dataset(name)
        assert spec.name == name
        assert spec.source in ("hf", "kaggle")
        assert spec.repo
        if not spec.files:
            assert spec.source == "hf", (
                f"{name}: only hf specs may use the empty-files snapshot lane"
            )
        assert spec.license_note
        assert spec.provenance_url
        assert spec.notes


def test_unknown_name_raises_keyerror_with_candidates():
    with pytest.raises(KeyError) as e:
        get_dataset("no_such_set")
    assert "no_such_set" in str(e.value)
    assert "wider_face" in str(e.value)


def test_expected_hashes_are_64_hex_or_none():
    for name in list_datasets():
        for f in get_dataset(name).files:
            if f.sha256_expected is not None:
                assert len(f.sha256_expected) == 64
                int(f.sha256_expected, 16)


def test_no_em_dashes_anywhere():
    import datasets as m
    import inspect
    src = inspect.getsource(m)
    assert "\u2014" not in src


def test_kaggle_specs_are_single_archive():
    for name in list_datasets():
        spec = get_dataset(name)
        if spec.source == "kaggle":
            assert len(spec.files) == 1, f"{name} must be a single kaggle archive"
            assert spec.files[0].path == "kaggle-archive.zip"
            assert spec.files[0].extract


def test_new_landmark_and_ir_entries():
    wflw = get_dataset("wflw")
    assert wflw.source == "kaggle"
    assert wflw.repo == "mrriandmstique/wflw-wider-facial-landmarks-in-the-wild"
    three = get_dataset("300w")
    assert three.source == "hf"
    assert three.repo == "quoctai219/300W"
    assert three.files[0].path == "300w_dataset.zip"
    aflw = get_dataset("aflw2000")
    assert aflw.repo == "mohamedadlyi/aflw2000-3d"
    cbsr = get_dataset("cbsr_nir")
    assert cbsr.repo == "gpreda/cbsr-nir-face-dataset"
    oulu = get_dataset("oulu_casia_nir")
    assert oulu.repo == "aryanbaibaswata/oulu-casia"
    for spec in (wflw, three, aflw, cbsr, oulu):
        assert spec.provenance_url
        assert spec.license_note
        assert spec.notes


def test_new_recognition_entries():
    lfw = get_dataset("lfw")
    assert lfw.source == "kaggle"
    assert lfw.repo == "jessicali9530/lfw-dataset"
    assert lfw.files[0].path == "kaggle-archive.zip"
    assert lfw.files[0].extract
    assert lfw.files[0].size_hint_bytes == 112_000_000
    cfpw = get_dataset("cfpw")
    assert cfpw.source == "kaggle"
    assert cfpw.repo == "chinafax/cfpw-dataset"
    assert cfpw.files[0].path == "kaggle-archive.zip"
    assert cfpw.files[0].extract
    assert cfpw.files[0].size_hint_bytes == 86_000_000
    bundle = get_dataset("aligned_fr_bundle")
    assert bundle.source == "kaggle"
    assert bundle.repo == (
        "yakhyokhuja/agedb-30-calfw-cplfw-lfw-aligned-112x112"
    )
    assert bundle.files[0].path == "kaggle-archive.zip"
    assert bundle.files[0].extract
    assert bundle.files[0].size_hint_bytes == 1_400_000_000
    for spec in (lfw, cfpw, bundle):
        assert spec.provenance_url == (
            "https://www.kaggle.com/datasets/" + spec.repo
        )
        assert "research" in spec.license_note.lower()
        assert spec.notes
    assert "deepfunneled" in lfw.notes
    assert "verify" in lfw.notes.lower()
    assert "verify" in cfpw.notes.lower()
    assert "500" in cfpw.notes
    assert "7000" in cfpw.notes
    assert "honestly" in cfpw.notes.lower()
    assert "112" in bundle.notes
    assert "pair" in bundle.notes.lower()
    assert "published-comparable" in bundle.notes


def test_pad_entries_pinned_mirrors():
    casia = get_dataset("casia_fasd")
    assert casia.source == "kaggle"
    assert casia.repo == "immada/casia-fasd"
    assert casia.files[0].path == "kaggle-archive.zip"
    assert casia.files[0].extract
    assert casia.files[0].size_hint_bytes == 2_200_000_000
    npu = get_dataset("oulu_npu")
    assert npu.source == "kaggle"
    assert npu.repo == "mizaku/oulu-npu-test"
    assert npu.files[0].path == "kaggle-archive.zip"
    assert npu.files[0].extract
    assert npu.files[0].size_hint_bytes == 500_000_000
    assert "minhtranv/oulu-npu-w-depth" in npu.notes
    assert "2_760_000_000" in npu.notes
    assert "record" in npu.notes.lower()
    celeba = get_dataset("celeba_spoof_hf")
    assert celeba.source == "hf"
    assert celeba.repo == "Ar4ikov/celebA_spoof"
    assert celeba.files == ()
    assert "snapshot_download" in celeba.notes
    assert "data/*" in celeba.notes
    for spec in (casia, npu, celeba):
        assert spec.provenance_url
        assert spec.license_note
        assert spec.notes


def test_snapshot_guard_signature():
    from fetch_data import validate_snapshot

    validate_snapshot(get_dataset("celeba_spoof_hf"))
    with pytest.raises(SystemExit):
        validate_snapshot(get_dataset("casia_fasd"))
    with pytest.raises(SystemExit):
        validate_snapshot(get_dataset("oulu_npu"))
    with pytest.raises(SystemExit):
        validate_snapshot(get_dataset("wider_face"))
