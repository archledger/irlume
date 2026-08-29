import pytest

from datasets import DatasetFile, DatasetSpec, get_dataset
from fetch_data import validate_spec


def _spec(source, files):
    return DatasetSpec(
        name="x", source=source, repo="o/d", files=tuple(files),
        license_note="l", provenance_url="https://example.com", notes="n",
    )


def test_kaggle_multi_file_rejected():
    with pytest.raises(SystemExit):
        validate_spec(_spec("kaggle", [
            DatasetFile(path="a.zip"), DatasetFile(path="b.zip"),
        ]))


def test_kaggle_single_file_ok():
    validate_spec(_spec("kaggle", [DatasetFile(path="kaggle-archive.zip")]))


def test_real_kaggle_specs_pass():
    for name in ["wflw", "aflw2000", "cbsr_nir", "oulu_casia_nir"]:
        validate_spec(get_dataset(name))


def test_hf_multi_file_ok():
    validate_spec(get_dataset("wider_face"))
