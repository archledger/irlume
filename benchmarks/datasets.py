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

_DATASETS: dict[str, DatasetSpec] = {_WIDER.name: _WIDER}


def get_dataset(name: str) -> DatasetSpec:
    try:
        return _DATASETS[name]
    except KeyError:
        known = ", ".join(sorted(_DATASETS))
        raise KeyError(f"unknown dataset {name!r}; known: {known}") from None


def list_datasets() -> tuple[str, ...]:
    return tuple(sorted(_DATASETS))
