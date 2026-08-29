"""Dataset registry for the calibration campaign.

Each entry pins the exact mirror irlume measured (see benchmarks/README.md:
mirror identity changes numbers). Archives are downloaded, sha256-recorded,
extracted, then deleted unless --keep-archives.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class DatasetFile:
    path: str
    sha256_expected: str | None = None
    extract: bool = True
    size_hint_bytes: int | None = None


@dataclass(frozen=True)
class DatasetSpec:
    name: str
    source: str  # "hf" | "kaggle"
    repo: str  # hf "owner/repo" or kaggle "owner/slug"
    files: tuple[DatasetFile, ...]
    license_note: str
    provenance_url: str
    notes: str


_WIDER = DatasetSpec(
    name="wider_face",
    source="hf",
    repo="CUHK-CSE/wider_face",
    files=(
        DatasetFile(
            path="data/wider_face_split.zip",
            extract=True,
            size_hint_bytes=3_500_000,
        ),
        DatasetFile(
            path="data/WIDER_val.zip",
            extract=True,
            size_hint_bytes=360_000_000,
        ),
        DatasetFile(
            path="data/WIDER_train.zip",
            extract=True,
            size_hint_bytes=1_470_000_000,
        ),
    ),
    license_note=(
        "WIDER FACE is provided by CUHK for non-commercial research; the "
        "exact terms stated on the source page are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url="https://huggingface.co/datasets/CUHK-CSE/wider_face",
    notes=(
        "Upload by the originating lab (CUHK-CSE). Official zip structure: "
        "WIDER_val/images/<event>/*.jpg plus wider_face_split/ ground truth. "
        "WIDER_test.zip is intentionally omitted: test annotations are not "
        "public; the AP protocol evaluates on val."
    ),
)

_THREE00W = DatasetSpec(
    name="300w",
    source="hf",
    repo="quoctai219/300W",
    files=(
        DatasetFile(
            path="300w_dataset.zip",
            extract=True,
            size_hint_bytes=2_140_000_000,
        ),
    ),
    license_note=(
        "300W is distributed for non-commercial research use per its source "
        "page; the exact terms stated there are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url="https://huggingface.co/datasets/quoctai219/300W",
    notes=(
        "This mirror ships the 300W common test subset only (600 png+pts "
        "pairs; no train or AFW images). That subset is the evaluation "
        "target. Mirror identity matters (see benchmarks/README.md): "
        "numbers are valid only for this mirror."
    ),
)

_WFLW = DatasetSpec(
    name="wflw",
    source="kaggle",
    repo="mrriandmstique/wflw-wider-facial-landmarks-in-the-wild",
    files=(
        DatasetFile(
            path="kaggle-archive.zip",
            extract=True,
            size_hint_bytes=760_000_000,
        ),
    ),
    license_note=(
        "WFLW is provided for non-commercial research use per its source "
        "page; the exact terms stated there are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url=(
        "https://www.kaggle.com/datasets/"
        "mrriandmstique/wflw-wider-facial-landmarks-in-the-wild"
    ),
    notes=(
        "Test split: 2500 images with 98-point landmark txts. Mirror identity "
        "matters (see benchmarks/README.md): numbers are valid only for this "
        "mirror."
    ),
)

_AFLW2000 = DatasetSpec(
    name="aflw2000",
    source="kaggle",
    repo="mohamedadlyi/aflw2000-3d",
    files=(
        DatasetFile(
            path="kaggle-archive.zip",
            extract=True,
            size_hint_bytes=87_000_000,
        ),
    ),
    license_note=(
        "AFLW2000-3D is provided for non-commercial research use per its "
        "source page; the exact terms stated there are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url="https://www.kaggle.com/datasets/mohamedadlyi/aflw2000-3d",
    notes=(
        "Ships 2000 jpgs with .mat annotations. Mirror identity matters (see "
        "benchmarks/README.md): numbers are valid only for this mirror."
    ),
)

_CBSR_NIR = DatasetSpec(
    name="cbsr_nir",
    source="kaggle",
    repo="gpreda/cbsr-nir-face-dataset",
    files=(
        DatasetFile(
            path="kaggle-archive.zip",
            extract=True,
            size_hint_bytes=1_200_000_000,
        ),
    ),
    license_note=(
        "CBSR NIR is research/education only per benchmarks/README.md; the "
        "exact terms stated on the source page are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url="https://www.kaggle.com/datasets/gpreda/cbsr-nir-face-dataset",
    notes=(
        "Bmp images. Mirror identity matters (see benchmarks/README.md): "
        "numbers are valid only for this mirror. The removed IR adapter was "
        "trained on this set, so results here are in-training-set numbers."
    ),
)

_OULU_CASIA_NIR = DatasetSpec(
    name="oulu_casia_nir",
    source="kaggle",
    repo="aryanbaibaswata/oulu-casia",
    files=(
        DatasetFile(
            path="kaggle-archive.zip",
            extract=True,
            size_hint_bytes=1_200_000_000,
        ),
    ),
    license_note=(
        "Oulu-CASIA NIR is research only per benchmarks/README.md; the exact "
        "terms stated on the source page are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url="https://www.kaggle.com/datasets/aryanbaibaswata/oulu-casia",
    notes=(
        "Layout: Oulu_CASIA_NIR_VIS/NI/<lighting>/<subject>/. Mirror "
        "identity matters (see benchmarks/README.md): numbers are valid only "
        "for this mirror."
    ),
)

_DATASETS: dict[str, DatasetSpec] = {
    _WIDER.name: _WIDER,
    _THREE00W.name: _THREE00W,
    _WFLW.name: _WFLW,
    _AFLW2000.name: _AFLW2000,
    _CBSR_NIR.name: _CBSR_NIR,
    _OULU_CASIA_NIR.name: _OULU_CASIA_NIR,
}


def get_dataset(name: str) -> DatasetSpec:
    try:
        return _DATASETS[name]
    except KeyError:
        known = ", ".join(sorted(_DATASETS))
        raise KeyError(f"unknown dataset {name!r}; known: {known}") from None


def list_datasets() -> tuple[str, ...]:
    return tuple(sorted(_DATASETS))
