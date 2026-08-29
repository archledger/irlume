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

_LFW = DatasetSpec(
    name="lfw",
    source="kaggle",
    repo="jessicali9530/lfw-dataset",
    files=(
        DatasetFile(
            path="kaggle-archive.zip",
            extract=True,
            size_hint_bytes=112_000_000,
        ),
    ),
    license_note=(
        "LFW is provided for non-commercial research use per its source "
        "page; the exact terms stated there are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url="https://www.kaggle.com/datasets/jessicali9530/lfw-dataset",
    notes=(
        "Must contain the lfw-deepfunneled images; verify at download before "
        "benchmarking. The committed 99.03 percent accuracy is on "
        "deepfunneled. Mirror identity matters (see benchmarks/README.md): "
        "numbers are valid only for this mirror."
    ),
)

_CFPW = DatasetSpec(
    name="cfpw",
    source="kaggle",
    repo="chinafax/cfpw-dataset",
    files=(
        DatasetFile(
            path="kaggle-archive.zip",
            extract=True,
            size_hint_bytes=86_000_000,
        ),
    ),
    license_note=(
        "CFPW is provided for non-commercial research use per its source "
        "page; the exact terms stated there are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url="https://www.kaggle.com/datasets/chinafax/cfpw-dataset",
    notes=(
        "Official protocol: 500 identities, 10 folds, 7000 pairs; verify at "
        "download. If the mirror is short, score what exists and label it "
        "honestly. Mirror identity matters (see benchmarks/README.md): "
        "numbers are valid only for this mirror."
    ),
)

_ALIGNED_FR_BUNDLE = DatasetSpec(
    name="aligned_fr_bundle",
    source="kaggle",
    repo="yakhyokhuja/agedb-30-calfw-cplfw-lfw-aligned-112x112",
    files=(
        DatasetFile(
            path="kaggle-archive.zip",
            extract=True,
            size_hint_bytes=1_400_000_000,
        ),
    ),
    license_note=(
        "AgeDB-30, CALFW, CPLFW and LFW are each provided for non-commercial "
        "research use per their source pages; the exact terms stated there "
        "are quoted verbatim into PROVENANCE.md at download time."
    ),
    provenance_url=(
        "https://www.kaggle.com/datasets/"
        "yakhyokhuja/agedb-30-calfw-cplfw-lfw-aligned-112x112"
    ),
    notes=(
        "AgeDB-30, CALFW, CPLFW and LFW aligned at 112x112 with shipped pair "
        "lists; the published-comparable lane. Mirror identity matters (see "
        "benchmarks/README.md): numbers are valid only for this mirror."
    ),
)

_CASIA_FASD = DatasetSpec(
    name="casia_fasd",
    source="kaggle",
    repo="immada/casia-fasd",
    files=(
        DatasetFile(
            path="kaggle-archive.zip",
            extract=True,
            size_hint_bytes=2_200_000_000,
        ),
    ),
    license_note=(
        "CASIA-FASD is provided for non-commercial research use per its "
        "source page; the exact terms stated there are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url="https://www.kaggle.com/datasets/immada/casia-fasd",
    notes=(
        "Single kaggle archive (~2.2 GB). Mirror identity matters (see "
        "benchmarks/README.md): numbers are valid only for this mirror."
    ),
)

_OULU_NPU = DatasetSpec(
    name="oulu_npu",
    source="kaggle",
    repo="mizaku/oulu-npu-test",
    files=(
        DatasetFile(
            path="kaggle-archive.zip",
            extract=True,
            size_hint_bytes=500_000_000,
        ),
    ),
    license_note=(
        "Oulu-NPU is provided for non-commercial research use per its source "
        "page; the exact terms stated there are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url="https://www.kaggle.com/datasets/mizaku/oulu-npu-test",
    notes=(
        "Start with mizaku/oulu-npu-test (~500 MB). Decision rule: if "
        "extraction shows test-split-only content and the bench needs "
        "sessions breadth, fetch minhtranv/oulu-npu-w-depth "
        "(2_760_000_000 bytes hint) as the fallback instead and record in "
        "the result JSON which mirror was used. Mirror identity matters "
        "(see benchmarks/README.md): numbers are valid only for this mirror."
    ),
)

_CELEBA_SPOOF_HF = DatasetSpec(
    name="celeba_spoof_hf",
    source="hf",
    repo="Ar4ikov/celebA_spoof",
    files=(),
    license_note=(
        "CelebA-Spoof is provided for non-commercial research use per its "
        "source page; the exact terms stated there are quoted verbatim into "
        "PROVENANCE.md at download time."
    ),
    provenance_url="https://huggingface.co/datasets/Ar4ikov/celebA_spoof",
    notes=(
        "Parquet shard snapshot lane: fetch with fetch_data.py --snapshot, "
        "which runs huggingface_hub snapshot_download with allow_patterns "
        "data/* into the dataset dir; no per-file resolve entries. Mirror "
        "identity matters (see benchmarks/README.md): numbers are valid "
        "only for this mirror."
    ),
)

_DATASETS: dict[str, DatasetSpec] = {
    _WIDER.name: _WIDER,
    _THREE00W.name: _THREE00W,
    _WFLW.name: _WFLW,
    _AFLW2000.name: _AFLW2000,
    _CBSR_NIR.name: _CBSR_NIR,
    _OULU_CASIA_NIR.name: _OULU_CASIA_NIR,
    _LFW.name: _LFW,
    _CFPW.name: _CFPW,
    _ALIGNED_FR_BUNDLE.name: _ALIGNED_FR_BUNDLE,
    _CASIA_FASD.name: _CASIA_FASD,
    _OULU_NPU.name: _OULU_NPU,
    _CELEBA_SPOOF_HF.name: _CELEBA_SPOOF_HF,
}


def get_dataset(name: str) -> DatasetSpec:
    try:
        return _DATASETS[name]
    except KeyError:
        known = ", ".join(sorted(_DATASETS))
        raise KeyError(f"unknown dataset {name!r}; known: {known}") from None


def list_datasets() -> tuple[str, ...]:
    return tuple(sorted(_DATASETS))
