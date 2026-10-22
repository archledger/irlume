# Certification extent: corpora, decision arms and the difference record

Research record for the ADR-0022 amendment of 2026-10-22 ("certification
corpora and decisions at full extent"), #1164. Reading and counting only: no
measurement ran for this record, no loading profile is admitted, `CERTIFIED`
stays empty and CPU authentication stays authoritative. Every count below
comes from committed files, cited by path and line, from the provenance
record of 2026-10-22 on the project share
(`artifacts/irlume/2026-10-22-1164-s73/provenance/NOTE.md`, with its
`SHA256SUMS`), or from file names, directory and archive listings and split
text through the script in section 13. No image, embedding or template was
opened, and the record holds aggregates only. It names no person: the
recorded data belongs to the maintainer and one other consenting household
member. Line numbers are those of origin/main `16f7fd2c`; of the files
cited, `crates/irlume-vision/src/lib.rs` and
`crates/irlume-vision/src/onnx/npu_tests.rs` differ from `98d310c7`, and
only the first one's cited lines moved.

## 1. Why the extent comes first

Item 4 forbids a new grant "at any threshold, fusion floor or
production-shaped decision" and item 5 reads the drift as a shift of the
threshold (ADR-0022 lines 323-340). Neither says over which comparisons. The
full-corpus run of 2026-10-22 on the UX5406S (share archive
`artifacts/irlume/2026-10-22-1053-xe-decisions/full-corpus-20261022T031950Z/`)
shows what a bounded subset can miss:

| Arm at 0.55 | Measured | CPU accepts | Nearest CPU score to the threshold | Log line |
|---|---|---|---|---|
| LFW protocol, genuine | 3,000 | 2,118 | 0.0002 | 86-87 |
| LFW protocol, impostor | 3,000 | 0 | 0.2087 | 88-89 |
| FairFace, consecutive pairs, all groups | 10,392 | 2 | 0.0019 | 90 |

The largest drift in that run was 5.96e-7 (log line 87). An impostor arm
whose nearest CPU score sits 0.2087 from the threshold cannot show a new
grant at any drift under 0.2, so it says nothing about item 4 at the drifts
this hardware produces. Fixing the extent before a run also keeps the extent
from being chosen after the result.

What the amendment changes: items 4 and 5 keep their rules, and the
amendment fixes what they run over (sections 3 to 7) and which enrollment
shapes an entry covers, those that both an impostor arm and an attack arm
reach (section 7). It changes item 8's record for recorded data of people
and for the three corpora whose terms restrict sharing: such arms leave the
measuring machine only as aggregates over their whole extent under a hiding
digest, once a validator run there as root has passed the record, and one
with a difference above a drift of 1e-5 is refused (section 8). It sets the
conditions of the separate runs for items 6 and 7, including how item 7's
cold compiles empty the run's cache (section 9).

## 2. What set each threshold

### 2.1 RGB 0.55

| Date | Source | What it records |
|---|---|---|
| 2026-06-28 08:08 -0400 | provenance record | archhost clones Hugging Face `marcelohaps/lfw` at `12a61458` ("LFW HF-ready", original non-aligned images, with the 10-fold `pairs.csv`) into its recognition dataset directory. |
| 2026-06-28 08:33 -0400 | commit `1bf31564` (message) | `irbench --lfw`: "Result (LFW 13,233 imgs / 5,749 ids / 87.3M impostor pairs on archhost): FAR @ 0.50 = 3e-5, beating the synthetic estimate (9.8e-5)" (`git log -1 --format=%B 1bf31564`, lines 11-13). Pairs are i < j, same identity genuine, otherwise impostor (`crates/irlume-cli/src/main.rs` lines 312-318 at that commit). |
| 2026-06-28 13:00 -0400 | commit `8c2d6ed9`, `docs/FAIRNESS.md` lines 14-26 | FairFace validation split, all pairs within each group, FAR at 0.50 per group. |
| 2026-06-28 18:30 -0400 | commit `11cf4a9e` (message and `lib.rs` comment) | 0.50 to 0.55, citing "3e-5 @ 0.50 / 2e-5 @ 0.55 (LFW, 87M pairs)" and FairFace ("0.50 only clears FMR≤1e-4 for the best demographic group"). The comment also cites "synthetic (SFHQ, 112M pairs) 9.8e-5 @ 0.50". |
| 2026-07-05 | commit `94bc56dc`, `docs/VERIFY.md` (now lines 122-125, 134-135) | Run over every pair of 13,233 images (87,549,528), 2.3e-3 at 0.50; no 0.55 figure; names Kaggle `jessicali9530/lfw-dataset` as "the source used here". |
| 2026-07-06 | commit `565d193c` | Replaces the `RGB_MATCH_THRESHOLD` doc's "3e-5 @ 0.50 and 2e-5 @ 0.55" with "2.3e-3 @ 0.50 and 2.0e-3 @ 0.55" over "87M impostor pairs" (`crates/irlume-core/src/lib.rs`, now lines 87-90); its message calls them "the measured" figures. |
| 2026-07-12 | commit `e9974e67` | Carries "2.0e-3 @ 0.55 on LFW" into the module doc (now line 9). 2.0e-3 appears in no other committed file (`git grep -n '2\.0e-3' origin/main`). |
| 2026-07-28 | commit `ae755dbc`, `docs/VERIFY.md` lines 134-140 | Relabels the all-pairs figure an upper bound; `irbench` refuses `--impostor-only` with `--lfw` (`crates/irlume-cli/src/main.rs` lines 2600-2615). |
| 2026-08-04 | `docs/recognition-results/data/lfw-aura.txt` lines 1-8, measured at `b8313f4` on archhost (`docs/recognition-results/data/MANIFEST.json` lines 12, 15, 48) | Identity-grouped re-run: 5,749 persons, 13,233 images, 0 without a face, 242,257 genuine and 87,307,271 impostor pairs; FAR 0.00003 at 0.50 and 0.00002 at 0.55; FRR 0.1798 and 0.2974. |
| 2026-08-04 | `docs/recognition-results/data/sfhq-aura.txt` lines 16-24, the same run (MANIFEST.json lines 17, 38-41) | SFHQ part 1, first 15,000 images in lexicographic order: 112,492,500 pairs, 0 without a face; FAR 4.71e-4 at 0.50 and 1.43e-4 at 0.55; 0.565 for 1e-4. |

The 2.3e-3 at 0.50 is VERIFY.md's figure; VERIFY.md gives no 0.55 value, and
the 2.0e-3 at 0.55 exists only in the `irlume-core` comments that `565d193c`
and `e9974e67` wrote. Both are all-pairs rates. Adding the genuine accepts
of `lfw-aura.txt` to its impostor accepts and dividing by every pair
(242,257 + 87,307,271 = 87,549,528) gives 2.294e-3 to 2.305e-3 at 0.50 and
1.959e-3 to 1.969e-3 at 0.55, over the rounding of the printed rates (script
output, section 13), which agrees with both printed figures. No committed
run prints 2.0e-3; it matches the all-pairs rate those counts imply. The
identity-grouped rate at 0.55 is 2e-5.

SFHQ is not a certification arm. Item 3 names LFW for RGB, and the message
of `11cf4a9e` rests 0.55 on LFW and FairFace. The June figure, 9.8e-5 at
0.50 over 112M pairs, named no subset, and the August record says "the
original AuraFace SFHQ figure could not be reproduced for lack of one"
(`docs/recognition-results/2026-08-05-buffalo-l.md` lines 70-74). The
committed re-run has figures at both 0.50 and 0.55: 4.71e-4 and 1.43e-4,
about 4.8 times the June figure at 0.50. 112M is every pair of 15,000
images, so the June run may also have used 15,000 images, but which ones is
not recorded. The `irlume-core` comment now gives the re-run's figures and
drops "cleaner than unconstrained real photos", which the identity-grouped
LFW rate of 3e-5 at 0.50 contradicts.

### 2.2 Which LFW copy

The provenance record of 2026-10-22 settles it:

| Fact | Source |
|---|---|
| archhost's recognition dataset directory for LFW is a git clone of `https://huggingface.co/datasets/marcelohaps/lfw` at `12a61458b56d0433d07269dc1d64368abf4f6b4d`, made 2026-06-28 08:08 -0400, 25 minutes before commit `1bf31564` | provenance record; `git show -s --format=%ad 1bf31564` gives 08:33:37 -0400 |
| archhost's saved benchmark script of 2026-08-04 runs `irbench --dir "$HOME/datasets-recog/lfw" ... --lfw --max-persons 999999` for the `lfw-aura` and `lfw-buffalo` legs | provenance record |
| The committed `lfw-aura.txt` (added in `c3f15ab4`, #280) has SHA-256 `2758d025fb2205bffb21f36e2223379669eb49c37fcee56f6fd3fa5455a11e8a`, the same as that script's output file of 2026-08-04 20:11:44 -0400 | provenance record; `git show origin/main:docs/recognition-results/data/lfw-aura.txt \| sha256sum`, run for this record |
| The measuring machine's original-image copy is file for file that clone: the SHA-256 of the sorted per-image SHA-256 list is `86d0a86d9294f76c87dec57770368cdb434c2d67d367b346e1abd80af090cd75` on both hosts (13,233 jpg) | provenance record |
| The Kaggle `jessicali9530/lfw-dataset` deep-funneled copy reached archhost on 2026-08-29; it is the copy of the all-pairs run of 2026-07-05 | provenance record; `docs/VERIFY.md` lines 122-125 |

So the original images are the threshold's own extent, and the deep-funneled
copy is a gating family because the published all-pairs upper bound cites
it. "The figure is stable to the variant" (VERIFY.md line 125) is not
established: the deep-funneled copy scores differently from the original
images for the ViT PAD cue
(`docs/research/2026-10-21-vit-dim-room-cue-evaluation.md` lines 126-131).
The same change qualifies that sentence, drops `--lfw` from VERIFY.md's
command (which `irbench` has refused with `--impostor-only` since
`ae755dbc`), and adds the identity-grouped command of MANIFEST.json line 15
with the Hugging Face copy named as its source. The Hugging Face card's
licence field is `other` and tells users to check the original dataset's
terms before publishing or redistributing it (the copy's local
`PROVENANCE.md`).

Both local copies hold 13,233 JPEG files with the same file names, so their
identity counts are equal (section 13). The Kaggle archive also carries
13,233 `__MACOSX/._*.jpg` AppleDouble entries (24,735 `__MACOSX` entries in
all), which a reader of the archive must skip; the extracted folder holds
none.

### 2.3 FairFace

| Group | Images | Faces | Pairs measured (unordered) | FAR 0.50 | FAR 0.55 | Threshold for 1e-4 | Ordered pairs | Consecutive pairs |
|---|---|---|---|---|---|---|---|---|
| Black | 1,556 | 1,395 | 972,315 | 4.37e-4 | 1.40e-4 | 0.575 | 2,419,580 | 1,555 |
| East Asian | 1,550 | 1,440 | 1,036,080 | 1.042e-3 | 4.17e-4 | 0.665 | 2,400,950 | 1,549 |
| Indian | 1,516 | 1,388 | 962,578 | 1.68e-4 | 9.5e-5 | 0.550 | 2,296,740 | 1,515 |
| Latino Hispanic | 1,623 | 1,514 | 1,145,341 | 2.52e-4 | 1.74e-4 | 0.650 | 2,632,506 | 1,622 |
| Middle Eastern | 1,209 | 1,096 | 600,060 | 4.50e-4 | 3.40e-4 | 0.685 | 1,460,472 | 1,208 |
| Southeast Asian | 1,415 | 1,341 | 898,470 | 7.46e-4 | 2.39e-4 | 0.610 | 2,000,810 | 1,414 |
| White | 2,085 | 1,885 | 1,775,670 | 1.05e-4 | 6.8e-5 | 0.505 | 4,345,140 | 2,084 |
| All | 10,954 | 10,059 | 7,390,514 | | | | 17,556,198 | 10,947 |

Images, faces, pairs, rates and thresholds come from
`docs/recognition-results/data/ff-<group>-aura.txt` (the "embedded",
"pairs=", "thr 0.50", "thr 0.55" and "[FAR≤1e-4]" lines); the ordered and
consecutive counts from file names (section 13). The 0.55 rates are also the
AuraFace column of `docs/recognition-results/2026-08-05-buffalo-l.md` lines
45-53. `docs/FAIRNESS.md` tabulates 0.50 only (lines 18-26). At 0.55 two
groups are at or under 1e-4 and five are above it, from 1.40e-4 to 4.17e-4;
no group is under 1e-4 at 0.50, and about 0.69 holds it for every group
(`docs/FAIRNESS.md` lines 28-31). The measurement dropped 895 images in
which its detector found no face and paired the other 10,059.

The copy is settled. All 14 committed `ff-<group>-{aura,buffalo}.txt` files,
added in `c3f15ab4` (#280; `git show --stat c3f15ab4` lists 14), are byte
for byte the outputs of archhost's saved benchmark script of 2026-08-04,
which ran on archhost's FairFace tree, one directory per group. That tree,
created 2026-06-28 09:40 -0400 before `docs/FAIRNESS.md` was committed at
13:00, has the same per-file digest list as the measuring machine's FairFace
copy (digest `8d71892e...`, 10,954 jpg), whose `PROVENANCE.md` names
`HuggingFaceM4/FairFace` configuration 0.25, validation split, commit
`54d573cdb8b5af490ba8da9da2799628f6e5c496`, object
`0.25/validation-00000-of-00001-951dbd63c8724ee1.parquet` with SHA-256
`d0cfac2888356b3d3fa3d837bc30961d8c860934e4c5df862e8cb87812bfa137`,
re-encoded at JPEG quality 95 with every derived file byte-checked
(provenance record; the copy's `PROVENANCE.md`). The August re-run
reproduced every group's June rate "to the printed digit"
(`2026-08-05-buffalo-l.md` lines 29-30). FairFace 0.25 validation is
therefore the threshold's own copy, and the 1.25 configuration is not a
family of this amendment. The dataset card declares CC BY 4.0.

### 2.4 The false-reject leg of 0.55

The `RGB_MATCH_THRESHOLD` comment rests 0.55's accept margin on live genuine
scores of the maintainer (`crates/irlume-core/src/lib.rs` lines 92-94), as
the message of `11cf4a9e` does: "Live genuine sits at 0.71+ so 0.55 keeps a
wide accept margin (no added false-rejects)"
(`git log -1 --format=%B 11cf4a9e`, lines 18-19). The 2026-08-05 record
measured that side with `irlume calcapture --n 25` sessions on archhost's
Logitech Brio (`--rgb /dev/video4 --ir /dev/video6`) and the Zenbook's
built-in camera (`docs/recognition-results/data/MANIFEST.json` lines 50-58;
`docs/recognition-results/2026-08-05-buffalo-l.md` lines 76-94). Each
session included a run of the shipped recognizer (MANIFEST.json line 51),
and of those runs the record states one thing: "Both live-capture sessions
carried an AuraFace anchor run that landed on the documented live floor"
(lines 34-36). The amendment and the rewritten comment cite that sentence
for the floor and claim no more. Lines 103-105 of the same record give the
margin over 0.55 of the buffalo_l floors in its table (lines 81-85), not of
the shipped recognizer's runs, so neither text cites them.

The repository holds only the sessions' aggregates: eight runs in
`docs/recognition-results/data/floor-aggregates.json`, three of them of the
shipped recognizer, keyed `aura-` and carrying the digest prefix of
`glintr100.onnx` (lines 7, 24 and 41; `crates/irlume-core/src/storage.rs`
lines 267-273). `aura-brio-desk` belongs to the Brio session, and
`aura-lamp` and `aura-lamp-redo` were both recorded on the UX5406S (host
fields, lines 23 and 40). The two minimum and mean pairs that lines 35-36 of
the 2026-08-05 record report are, rounded, those of `aura-brio-desk` and
`aura-lamp-redo` (lines 5-21 and 39-55). No committed text reports or
explains `aura-lamp` (`git grep -n aura-lamp origin/main` matches only the
two JSON keys), and its pairwise genuine scores did not land on that floor
(lines 22-38). The amendment therefore cites the anchor runs of the
2026-08-05 record for the floor and names the file only as the place where
the aggregates live; this record adds no statistic of these runs.

The raw records hold CPU embeddings, not frames. The committed derivation
reads from each sample only its embedding and brightness
(`docs/recognition-results/data/derive-floor-aggregates.py` lines 4-6 and
42-61), the "raw jsonl holds biometric embeddings and is not committed"
(MANIFEST.json line 57), and the record of facts settled with the
maintainer on 2026-10-22 (share,
`artifacts/irlume/2026-10-22-1164-s73/settled-facts-20261022.md`, item 9)
states that the saved Brio records hold CPU embeddings. An accelerator run
needs the frames, so these records cannot be replayed through one. The same
holds for the self-captured pairs that ADR-0004 makes its validation bed
(ADR-0004 lines 91-92), which are embedding records only (the same item).
The genuine side of certification is therefore carried by the recorded
frames of the manifest (section 7) and its named re-recordings. The
household member's older captures in that bed are not used.

### 2.5 IR

- Commit `d1c8cca7` (2026-06-26) states a full CBSR run, "7.7M pairs", with
  0.635 the only threshold holding 1e-4; it changes
  `crates/irlume-core/src/lib.rs` only (`git show --stat d1c8cca7`). 7.72M
  is every unordered cross-identity pair of 3,940 images (7,722,400, section
  13), so that run covered every unordered impostor pair. Its output is not
  in the repository: the committed pairwise CBSR results use 6,000 pairs per
  arm (`benchmarks/results-nir_results.json` lines 19, 33, 47).
- The sweep behind 0.635 keeps identities with more than 14 embedded frames,
  in sorted order (`benchmarks/securedark_sweep.py` lines 119-126), enrolls
  the first 11 (line 32) and probes the other 9 against every identity
  (lines 136-148): 197 identities, 1,773 genuine and 347,508 impostor
  decisions (`benchmarks/results-securedark-sweep.json` lines 3, 29-30). The
  OR arm grants on best-of-11 at the scaled threshold or on the raw mean
  centroid at the flat one (lines 177-199), 1.237e-4 at 0.635 (JSON lines
  183-185). Production has no centroid without a fitted calibration
  (`crates/irlume-auth/src/lib.rs` lines 2046-2076), so the OR arm is not a
  production decision.
- The release's own split: 1,576 gallery rows and 2,364 probe rows, 8 and 12
  per person, under the strict grammar `<name>.bmp,int,int,int,int`. In the
  certification copy both split files hold rows only; the copy of 2026-06-26
  also carried 11 and 14 lines of a web-page preamble (section 13).
- Tufts: the Tufts calibrated arm of the same sweep pairs each subject's
  sorted RGB and NIR images (`benchmarks/securedark_sweep.py` lines
  264-284), and the layout it reads is the Kaggle mirror's doubled
  `td-*-a/td-*-a` directories (`benchmarks/bench_nir_ext.py` lines 185-192).
  The figure cited for the shipped lambda is corrected separately (S0b, the
  ADR-0016 amendment).
- The live dark session of 2026-08-23: 30 authentications on minihost's
  NexiGo N930W in true dark, 23 granted
  (`docs/research/2026-08-22-securedark-v1.md` lines 148-165). Its frames
  were not found (section 7).

## 3. Copies and their terms

| Family | Source and revision | Derivation | File-list digest | Images | Class |
|---|---|---|---|---|---|
| lfw-orig | Hugging Face `marcelohaps/lfw` at `12a61458` | none; Git LFS object hashes verified | `86d0a86d9294f76c87dec57770368cdb434c2d67d367b346e1abd80af090cd75` | 13,233 | public |
| lfw-dfun | Kaggle `jessicali9530/lfw-dataset` (dataset 26922), `lfw-deepfunneled` | extracted; `__MACOSX` entries skipped | taken by S8 | 13,233 | public |
| fairface | `HuggingFaceM4/FairFace` 0.25 validation at `54d573cd`, parquet `d0cfac28...` | JPEG quality 95, byte-checked | `8d71892e...` | 10,954 | public |
| cbsr | Kaggle `gpreda/cbsr-nir-face-dataset` (dataset 6111478), mirror of OTCBVS dataset 07 | as published | `da3b1393...` | 3,940 | private |
| tufts | Kaggle `wahabarabo/tufts-faces` (dataset 7374993), TD_RGB_A and TD_NIR_A Sets 1-4 | as published | `5bf7f510f1411bd51ee3e2446addcee518828e5a3a0b3375400b616fe7540838` | 6,468 | private |
| oulu | Kaggle `aryanbaibaswata/oulu-casia` (dataset 10440823), NI and VL under Dark, Weak and Strong | as published | taken by S8 | 64,912 | private |

A file-list digest is the SHA-256 of the sorted list of per-file SHA-256
values. The provenance record computed the full or abbreviated values above
on each host without moving any image; S8 takes every digest in full, and
the validator holds them. The Kaggle version current at each download was
not recorded, so for the Kaggle copies the file-list digest is the revision.

The maintainer chose the Kaggle copies as sources on 2026-10-22. The LFW
threshold copy is itself a re-post, so a rule that refused re-posted copies
would have refused the threshold's own evidence. The owners' terms are
quoted here and put to the maintainer; they are not accepted on the
maintainer's behalf.

- CBSR. OTCBVS, which serves the dataset as its benchmark dataset 07: "This
  benchmark is to be used for educational and research purposes only, and
  this benchmark must be acknowledged by the users"
  (http://vcipl-okstate.org/pbvs/bench/, read 2026-10-22). CASIA's NIR Face
  Database page: "The database is released for research and educational
  purposes. ... All rights of the CASIA NIR Face database are reserved. Any
  person or organization is not permitted to distribute, publish, copy, or
  disseminate this database." Its release agreement, rule 1: "Without prior
  approval from Prof. Stan Z. Li, the creator of the database, the CASIA NIR
  Face Database, either entirely or partly, should not be further
  distributed, published, copied, or disseminated in any way or form, no
  matter for profitable use or not"; rule 5 asks that Li et al. 2007 be
  cited "in all documents and papers that report experimental results based
  on the CASIA NIR Face database"
  (http://www.cbsr.ia.ac.cn/english/NIR_face%20Databases.asp and its
  `NIR_agreements.pdf`, read 2026-10-22). The Kaggle mirror lists MIT (its
  metadata in the provenance record); the owners' terms govern.
- Tufts. The lab's own Kaggle page (`kpvisionlab/tufts-face-database`,
  metadata in the provenance record): "The researcher shall use the Database
  only for non-commercial research and educational purposes. ... The
  Researcher may not provide research associates and colleagues with access
  to the Database. The distribution of this database to any parties that
  have not read and agreed to the terms and conditions of usage is strictly
  prohibited. ... No permission is granted to reproduce the database or post
  into any webpage or any other storage means." The mirror lists the licence
  `other` with no description.
- Oulu-CASIA. The Kaggle mirror lists the licence `unknown`; no primary
  terms were found, and the project page directs users to its maintainer
  (the copy's `PROVENANCE.md`). irlume's dataset registry classifies it
  research-only (`benchmarks/README.md` line 37).
- LFW and FairFace. The LFW card's licence field is `other`; FairFace is CC
  BY 4.0 (each copy's `PROVENANCE.md`).

Consequence. CBSR, Tufts and Oulu-CASIA images stay on the measuring machine
and never reach git, the share, a cloud drive or another host. Every arm
that consumes one of their scores is private (section 8): CASIA's rule 1
covers the database "either entirely or partly", and a per-comparison list
with file ordinals and exact margins is per-image data derived from it;
Tufts forbids colleagues' access; and Oulu-CASIA has no terms that would
allow more. Their arms are archived as aggregates only, as recorded data is.

Citations that results on these corpora carry: for CBSR, "IEEE OTCBVS WS
Series Bench; Center for Biometrics and Security Research (CBSR)
www.cbsr.ia.ac.cn; AuthenMetric Co. Ltd (Beijing) www.authenmetric.com" and
S. Z. Li, R. Chu, S. Liao and L. Zhang, "Illumination Invariant Face
Recognition Using Near-infrared Images", IEEE TPAMI 29(4), 2007, pp.
627-639; for Tufts, K. Panetta et al., "A comprehensive database for
benchmarking imaging systems", IEEE TPAMI, 2018, and
http://tdface.ece.tufts.edu/; for FairFace, K. Karkkainen and J. Joo, WACV
2021.

## 4. Pairwise arms

| Arm | Ordered genuine | Ordered impostor | Reported sub-arm | Class |
|---|---|---|---|---|
| LFW, each copy | 484,514 | 174,614,542 | the 6,000 protocol pairs | public |
| FairFace, each group its own arm | | 17,556,198 | 10,947 consecutive pairs | public |
| CBSR | 74,860 | 15,444,800 | | private |
| Tufts RGB | 96,162 | 10,359,360 | | private |
| Tufts NIR | 96,162 | 10,359,360 | | private |
| Oulu-CASIA NI, dark / weak / strong | 1,464,038 / 1,482,038 / 1,361,614 | 114,776,704 / 115,882,684 / 106,351,648 | | private |
| Oulu-CASIA VL, dark / weak / strong | 1,622,446 / 1,578,716 / 1,372,968 | 127,188,704 / 123,581,440 / 106,340,294 | | private |

Every comparison is an accelerator probe against a CPU template. The CPU
reference score is symmetric; the accelerator-probe score is not, which is
why each unordered pair runs twice. Tufts identities are the subject
directories: each of the 110 appears in exactly one of Sets 1-4, so the
set-qualified identity of `bench_nir_ext.py` and the merged identity of
`securedark_sweep.py` agree, and the per-subject counts are equal in both
modalities (section 13). Oulu-CASIA identities are the 80 subject
directories; each lighting and modality is its own arm. Oulu-CASIA set no
threshold; it runs because it is the only public corpus here with NIR and
visible images of the same subjects under recorded lightings, and items 4
and 5 apply to it as to every arm.

## 5. Decision arms

Rules:
- An enrollment of n takes the first n images of the identity that the CPU
  reference can align, in the arm's order, as the sweep takes its first 11
  embedded frames (`securedark_sweep.py` lines 122-126, 136-137). An
  identity enters size n only with at least n + 1 alignable images.
- Two orders, for every decision arm on a corpus except the two replayed
  splits, which keep their own: sorted relative paths, and a shuffle that
  sorts each identity's images by the SHA-256 of the UTF-8 bytes of the
  copy's file-list digest in lowercase hexadecimal, one tab (0x09) and the
  image's relative path. The amendment gives the same definition.
- A probe the CPU reference cannot align leaves every decision it would have
  made. Each arm records enrollments and decisions enumerated (from file
  names), excluded and measured.
- Templates are CPU embeddings through the production scan path; probes are
  accelerator embeddings through the production probe helpers under section
  2's probe rule, in the measuring process that a later amendment defines;
  the decision is that of the production identity arms (the lit arms of
  `identity_arms.rs`, the dark arms of `ir_assessment.rs`) at the threshold
  its shape uses.
- A face never owns two profiles: enrollment folds a capture that matches an
  existing profile into it, and creates a new profile only for a face that
  matches none (`crates/irlume-auth/src/lib.rs` lines 9603-9636 and
  10890-10894; `crates/irlume-core/src/storage.rs` lines 18-21). Several
  profiles are therefore several people, which is what the households model.

Counts by file names, per order (section 13):

| Arm | Enrollments or households | Genuine decisions | Impostor decisions |
|---|---|---|---|
| LFW single identity, n = 1 to min(90, m - 1), each copy | 6,799 | 133,025 | 89,766,767 |
| LFW households of 2, from the 32 identities with at least 31 images by file names, k = 1 to 30 | 496 | 1,687,020 | 194,758,740 |
| LFW households of 3, same members | 4,960 | 25,305,300 | 1,936,845,900 |
| CBSR single identity, n = 1 to 19 | 3,743 | 37,430 | 14,672,560 |
| CBSR households of 2, k = 1 to 19 | 19,306 | 7,336,280 | 1,430,574,600 |
| CBSR households of 3, k = 1 to 19 | 1,254,890 | 715,287,300 | 92,510,490,800 |
| CBSR replay, the sweep split (11 and 9, within one session, `securedark_sweep.py` lines 32-37), one order | 197 | 1,773 | 347,508 |
| CBSR replay, the release split (8 and 12, as distributed), one order | 197 | 2,364 | 463,344 |
| Tufts single identity, k paired scans, k = 1 to min(30, m - 1) | 2,918 | 47,496 | 9,348,000 |
| of which calibrated, k = 3 up | 2,700 | 41,357 | 8,649,454 |
| Tufts households of 2, k = 1 to min(30, smallest member less one) | 5,886 | 4,959,030 | 465,232,702 |
| of which calibrated, k = 3 up | 5,886 | 4,296,018 | 427,860,382 |
| Tufts households of 3, same rule | 209,934 | 258,999,978 | 15,631,183,602 |
| of which calibrated, k = 3 up | 209,934 | 223,528,836 | 14,310,691,038 |

Tufts holds 1 to 36 images per subject: one subject has a single image and
enrolls in no arm, though its image is an impostor probe, and 47 subjects
have 31 or more (section 13). Thirty LFW identities exceed 30 templates.
Their scans fill several profiles, which no enrollment does; the arm still
reaches the RGB thresholds for 31 to 90 templates that households reach, and
the filled layout (30, 30, rest) and the balanced layout both run. The RGB
verdict must be identical in both, since it takes the best over all scans at
the threshold for their total (`crates/irlume-auth/src/lib.rs` lines
8197-8202). Every CBSR and Tufts arm also runs at the dim-light fallback
bar.

Outside the two replays, which keep their protocols' probe sets, impostor
probes are every image of every identity outside the enrollment.

Two notes on reading these counts:
- Households reuse probes and templates, so one comparison can repeat across
  many decisions, in the numerator and in the denominator. The records also
  give the distinct probe images per arm.
- For a raw best-of-n decision, a new impostor grant needs a template whose
  accelerator-probe score clears the threshold while every CPU score stays
  under it; that template's pair is then a new grant in the pairwise arm at
  the same threshold value, which the pairwise arms judge. The decision arms
  add the decision-level budgets of items 4 and 5, the calibrated and
  centroid scores, and the composed verdicts.

The thresholds are generated, not listed (section 13 counts them): the RGB,
dim-light fallback and dark bases scaled for every template count, which
also covers the centroid bars, since the lit centroid uses the fallback base
scaled by the profile count plus the margin and the dark centroid the dark
base scaled by the profile count (`crates/irlume-auth/src/identity_arms.rs`
lines 83-93; `crates/irlume-auth/src/ir_assessment.rs` lines 491-502). The
adapted base 0.40 is left out because a configured IR adapter keeps the
probes on CPU (`crates/irlume-auth/src/npu_probe.rs` lines 71-72 and 94-99).
Each base gives 102 distinct values up to the cap, which binds from 102
templates; the values for 91 to 102 templates are judged although no
admitted shape reaches them, since an admitted enrollment holds at most 90
scans.

## 6. Fusion

`fuse` grants when the weighted mean of the two sigmoid scores reaches
`FUSION_PROB_THRESHOLD` 0.50, each score reaches
`FUSION_MIN_PER_MODALITY_PROB` 0.10, and the IR weight is positive
(`crates/irlume-core/src/fusion.rs` lines 34, 38, 102-115). With the shipped
sigmoid coefficients (lines 26-31) the floor 0.10 is a cosine of about
0.2448 for RGB and 0.3505 for IR, and a score of 0.50 a cosine of about
0.3346 and 0.4054 (section 13). Each weight is a ramp from 0.2 at the low
knee to 1.0 at the high knee of the face-box luma and flat outside them
(lines 56-68): 60 and 130 for RGB, 35 and 110 for IR. Production takes those
lumas as the mean over the detected face box
(`crates/irlume-auth/src/lib.rs` lines 6553-6556 and 6573-6576) and hands
the weights to `fuse` in `lit_ir_arms`
(`crates/irlume-auth/src/identity_arms.rs` lines 76-82).

Sources. Recorded pairs are fused as recorded: each ordered pair of Tufts
paired scans gives one RGB and one NIR cosine (96,162 genuine and 10,359,360
impostor combinations), and the maintainer's paired frames give their own.
Corpus combinations pair every RGB comparison of each LFW copy and of
FairFace (impostor only) with every CBSR and every Tufts NIR comparison,
each pairing of sources its own arm, and every Oulu-CASIA visible comparison
with every NIR comparison of the same lighting. At the decision level the
best scores of single-identity decisions of the same n combine: n = 1 to 19
with CBSR and 1 to 30 with Tufts, in each order. Decision arms on paired
data, the Tufts single-identity and household arms and the enrolled users'
arms, run the full lit decision of `lit_ir_arms`, fusion included, at every
grid point, so the fused verdict of every admitted multi-profile shape with
IR is reached by the Tufts households.

Classes: genuine with genuine is the genuine class; impostor with impostor,
and the two mixed classes, are negative arms. Postures: in the sequential
posture neither fusion nor the RGB-primary arm grants
(`crates/irlume-auth/src/identity_arms.rs` lines 34-43 and 94;
`crates/irlume-auth/src/lib.rs` lines 1462-1464), and the arm checks that
neither does on either device. The arm's d is its largest drift over the
cosines it combines.

The grid. Per modality it holds the two knees, and the lowest and highest
recorded face-box luma, rounded outward to whole units, where they lie
strictly between the knees: at most four values per modality and sixteen
grid points. Each point's weights come from the production
`rgb_quality_weight` and `ir_quality_weight`. Every weight production can
give lies between the values at the two knees, 0.2 and 1.0, so the grid
spans the whole production range of weight pairs, ratios from 0.2 to 5, and
the recorded range's corners inside it. Production uses every ratio in that
range, since face-box luma is continuous. Brightness is an input of the
attempt, as the image is, and the arm samples it at the grid as the corpora
sample faces; items 4 and 5 apply at every grid point.

With r the ratio of the RGB weight to the IR weight, the fused score is
`(r*p_rgb + p_ir) / (r + 1)`. Its derivative in r, `(p_rgb-p_ir)/(r+1)^2`,
has one sign, so the fused score moves monotonically from p_ir toward p_rgb
as r grows, and the floors do not depend on r. Over an interval of ratios a
combination's grant set is therefore empty, the whole interval, or the part
on one side of a crossing ratio. A combination accepted at some ratio of the
range is accepted at one of the two extreme grid points (the lowest RGB
value with the highest IR value, and the reverse), and a genuine combination
rejected at some ratio is rejected at one of them. The arm counts these
range-wide accepts and rejects for both devices and applies items 4 and 5 to
them as well. A range-wide new grant, a combination the CPU denies at both
extremes and the accelerator grants at one, is already a new grant at that
grid point.

Counting at one grid point. For a fixed RGB cosine x and fixed weights the
grant only grows with the IR cosine y (the sigmoids increase and the floors
are lower bounds; `fusion.rs` lines 46-52, 102-108). It holds exactly when y
is at least Y(x), where Y(x) is the IR cosine at which p_ir reaches the
larger of 0.10 and `0.5 + r*(0.5 - p_rgb)`, and never when p_rgb < 0.10.
- Accept counts: per device and per IR class, one search per RGB score for
  Y(x) in that device's sorted IR scores. Item 5's shifts search for Y(x +
  d) - d and Y(x - d) + d on the CPU scores. The range-wide counts search
  for the smaller and the larger of Y at the two extreme points.
- New grants: each accelerator cosine lies within d of the CPU's and the
  grant grows with each, so an accelerator grant implies a CPU grant at (x +
  d, y + d). A combination the CPU denies and the accelerator grants at that
  point therefore has Y(x + d) - d <= y < Y(x). Two searches per RGB score
  give the index range of that band; the sizes, summed, are the candidate
  count K, known before any `fuse` call. Each candidate runs through the
  production `fuse` with that grid point's production weights on both
  devices, the differences are listed, and their margins are taken there.
- Rounding: Y(x) comes from closed-form inverse sigmoids in f64, while
  `fuse` computes in f32. Each boundary is therefore widened by a rounding
  band, and every IR score inside the band is decided by the production
  `fuse`, not by the closed form. A test holds the closed form to `fuse` on
  a dense grid of cosines and weights and on every candidate.
- Sweeps: with each device's RGB scores sorted once, Y(x) does not increase
  along them, so every search becomes one merge of two sorted lists.

Margins. At its grid point, each device's margin is the smallest equal shift
of both input cosines that flips that device's verdict there. The grant
grows with each cosine and each accelerator cosine lies within d of the
CPU's, so a shift of d toward the other device's verdict reaches it: each
margin is at most d. The margin is in cosine units on purpose. The fused
score's own distance to 0.50 is not bounded by d, because the sigmoids'
slopes reach A/4, about 6.1 per cosine unit for RGB and 10.0 for IR.

Where this arm is likeliest to fail. The floors are thresholds inside the
impostor distributions. LFW's impostor comparisons have a 99th percentile of
0.219 and a 99.9th of 0.295 (`docs/recognition-results/data/lfw-aura.txt`
line 4), so between 0.1% and 1% of them, 174,614 to 1,746,145 ordered
comparisons per copy, lie above the RGB floor of 0.2448. A log-linear
reading between the two percentiles, an estimate only, puts about 48 ordered
LFW impostor comparisons of the two copies within 1e-6 below the floor
(section 13). With a genuine IR score near 1 (the CBSR genuine mean is
0.855, `crates/irlume-core/src/lib.rs` line 102), the RGB floor decides the
fused verdict at every ratio up to 1.25, since at p_rgb = 0.10 and p_ir = 1
the fused score reaches 0.50 exactly when r <= 1.25. One such RGB comparison
whose accelerator score crosses the floor while its CPU score does not is
then a new grant with nearly every genuine IR comparison; the estimate puts
about 3.6 million combinations with CBSR and 4.7 million with Tufts in that
band. The amendment does not relax item 4 for this; a failure there is the
answer.

## 7. Recorded sessions and enrolled users' arms

The manifest. A private manifest on the measuring machine fixes the recorded
data: SHA-256
`3236ea19bda75b5afcb66afb4d72ea4c67c7f0ab2299c7daa0547a98938c84a9`, kept on
the laptop in a directory of mode 0700. Its per-category counts, from the
record of facts settled with the maintainer on 2026-10-22 (share,
`artifacts/irlume/2026-10-22-1164-s73/settled-facts-20261022.md`, item 2):

| Category | Camera | Sessions |
|---|---|---|
| Genuine, the maintainer | Zenbook built-in, IR bursts and RGB | 39 |
| Genuine, the maintainer | NexiGo | 10 |
| Genuine, the maintainer | Zenbook RGB webcam | 3 |
| Genuine, one other consenting household member | Zenbook RGB webcam | 1 |
| Presentation attacks, all showing the maintainer's face | Zenbook | 8 |
| Presentation attacks, all showing the maintainer's face | NexiGo | 11 |
| No-face control | Zenbook | 1 |
| All | | 73 |

Public text gives categories and counts only, never folder names, people or
frames. An arm's extent is every frame of every session the manifest lists
in its category. The manifest fixes which sessions and categories make up
the extent. It was made by a survey of names, counts, dates and text notes
that opened no image (the project ledger on the share, `project-irlume.md`,
checkpoint of 2026-10-22 13:14:41 UTC), so it cannot hold a modality read
from decoded frames, and no record says that it holds a digest of each
session's file list. Before any run, local code therefore derives from it a
run manifest, which stays beside it on the measuring machine: every row of
`3236ea19...` kept, and for each session its camera, its modality read from
the decoded channel count (not a directory name) and the SHA-256 of its file
list. The record of each run names the run manifest by its SHA-256. A file
under the manifest's root that no row covers, or a changed file-list digest,
refuses the run, and a session of anyone who has not consented is neither
listed nor kept under the root, so no recording of a third party enters a
negative arm.

What the manifest holds of the attack evidence. The attack recordings of
the 2026-07-17 PAD candidate evaluation
(`docs/pad-results/2026-07-17-third-party-pad-candidates.md`): the four live
banner runs on the NexiGo and the three on the Zenbook, the phone attacks and
the offline banner corpus. The session's own log places the four banner runs
on the NexiGo HelloCam N930W (IR `/dev/video6`), which corrected their first
filing by folder name (ledger checkpoint of 2026-10-22, after 14:30 UTC). It
also holds the seven NexiGo attack bursts cited by
`docs/research/2026-08-21-flir-public-nir-revalidation.md` line 34, in whose
252 frames no face is detectable in IR (lines 46-48).

What the manifest does not hold. Six recordings that earlier decisions rest
on are not in it. Their frames were not found on the laptop, minihost (every
home, `/srv` and `/var/lib`, searched as root, by name and by date), the
fleet ThinkPad (by date), archhost (its live home and the saved copy of its
old disk, by name and by date) or the pCloud archives (searches of
2026-10-22):
- the IR liveness self-test of 2026-06-30
  (`docs/pad-results/2026-06-30-ir-liveness-selftest.md`), behind ADR-0013's
  breach figure (line 23);
- the re-measurement of 2026-07-27 at the FLIR threshold of 0.9
  (`docs/pad-results/2026-07-17-third-party-pad-candidates.md` lines
  116-147; ADR-0013 lines 91-92);
- the #516 fleet banner runs (ADR-0013 lines 190-195), which kept one score
  per call;
- the live dark session of 2026-08-23 behind 0.635, 30 authentications on
  minihost's NexiGo N930W in true dark
  (`docs/research/2026-08-22-securedark-v1.md` lines 148-165; ADR-0016); the
  record keeps its scores only;
- the 2026-08-22 ViT live corpus
  (`docs/research/2026-08-22-screen-attack-pad-survey.md` line 245), behind
  the ViT cue's qualification (ADR-0013 lines 103-105);
- the 2026-08-12 flrgb live session, the corpus of the 2026-08-21 offline
  ViT evaluation (`docs/research/2026-08-21-vit-liveness-pad-evaluation.md`
  lines 9-11).

The only saved research corpus found, an early-August set of 264 files on
archhost's saved disk, stays on that disk and is not in the manifest. Each
missing recording is re-recorded under its original protocol in the
maintainer's approved attended session, and a later manifest names each
re-recording as the replacement of its session; no entry is added before
then.

The genuine side. The false-reject leg of 0.55 (section 2.4) holds CPU
embeddings, not frames, so the genuine side of certification is the
manifest's genuine sessions and the re-recordings.

Enrollments. Each person's enrollments hold one profile (section 5). Per
camera, an enrollment of shape (n_rgb, n_ir) takes that person's first n_rgb
frames the CPU reference can align, in the manifest's order, keeps the
paired IR frame of the first n_ir of them, and fits the calibration as
enrollment fits it, which is from 3 pairs (`crates/irlume-core/src/calib.rs`
line 34); production calibrates any probe with each profile's map before
scoring (`crates/irlume-auth/src/lib.rs` lines 2046-2052). The maintainer's
enrollments take every shape 0 <= n_ir <= n_rgb <= 30 that the camera's
recorded modalities allow, 495 shapes where IR is recorded (465 with IR, 30
without) and 30 where only RGB is; the household member's take every n_rgb
from 1 to 30 without IR, as far as the session's frames allow while keeping
a probe. Every other genuine frame of that person and camera is a genuine
probe.

| Arm | Genuine probes | Zero-effort impostor population, at every shape |
|---|---|---|
| Lit RGB | the person's other recorded RGB frames | every alignable image of both LFW copies and FairFace; the household member's frames against every maintainer enrollment, same camera for the Zenbook enrollments; the maintainer's RGB frames against every household-member enrollment |
| Lit IR fallback and calibrated centroid | the maintainer's other recorded IR frames | every alignable CBSR and Tufts NIR image, calibrated with the enrolled person's map |
| Dark best-of-n and dark centroid | the maintainer's other recorded dark-path frames | the same NIR population |
| Fusion | the person's own recorded RGB and IR pairs, at their own brightness and at every grid point | every combination of the RGB and NIR populations above, and the two mixed classes, at every grid point of section 6, both postures |
| Attacks | none; each attack session is a negative arm against every maintainer enrollment from the camera that recorded it, at every shape, and against the household enrollments built from them (below) | those enrollments also run against the populations above; the impostor side of the household shapes is the Tufts and LFW households (section 5) |
| No-face control | none; a negative arm against every enrollment the attack arms build from its camera | the one arm that may measure nothing, since the CPU-only pass may exclude all of its frames |

A comparison of a public image with an enrolled person's template is a
comparison of that person's data, so every arm in this table is private
(section 8), the public impostor populations included.

Attacks on household accounts. Production scales the RGB, fallback and dark
thresholds by the enrollment's scan count over every profile, and the
centroid bars by its profile count, all through `scaled_threshold`
(`crates/irlume-core/src/lib.rs` lines 178-184). The RGB arm takes
`scans.len()` over every profile's scans (`crates/irlume-auth/src/lib.rs`
lines 8197-8202; `crates/irlume-core/src/storage.rs` lines 347-359); the
fallback and dark bars take `n_templates`, summed over profiles
(`crates/irlume-auth/src/lib.rs` line 2036;
`crates/irlume-auth/src/identity_arms.rs` lines 88-89;
`crates/irlume-auth/src/ir_assessment.rs` lines 492-501); and both centroid
bars take the profile count (`identity_arms.rs` lines 90-93 with
`crates/irlume-auth/src/lib.rs` line 8253; `ir_assessment.rs` line 500 with
line 397). An attack showing the maintainer's face to an account of two or
three profiles of k scans is therefore decided at the values for 2k or 3k
templates, up to 90, and at the two- and three-profile centroid bars. The
dark values for 31 to 90 templates run from 0.7093 to 0.7324 (section 13),
about 0.06 above the IR cosine at which ADR-0002 measured the enrolled
user's vinyl banner, 0.650 (`crates/irlume-core/src/lib.rs` lines 128-130).
Item 4 forbids a new grant to an attack as to an impostor (ADR-0022 lines
323-329), and ADR-0033 repeats the rule "over both the impostor corpus and
the presentation-attack corpus" (lines 144-147).

The attack arms therefore also run on household enrollments. Each joins a
maintainer enrollment of shape (k, k) or (k, 0) to one or two companion
profiles of the same shape, each fitted as enrollment fits it. The
companions of (k, k) are the Tufts subjects that the Tufts households of
that k draw from, those with at least k + 1 images: 109 for k = 1 to 13, 90
at k = 26, 48 at k = 27 and 47 from k = 28 to 30. Those of (k, 0) are the 32
identities of the LFW households and the household member. Every companion
and every pair of companions joins, the corpus companions' images in both
orders: per maintainer camera and order, 149,515 household enrollments of
shape (k, k) and, without the household member, 15,840 of shape (k, 0), for
k = 1 to 30 (section 13). Each attack frame is also compared with every
template of the maintainer's enrollments from its camera, an RGB frame at
every RGB value of the generated set and an IR frame at every fallback and
dark value, and with the calibrated centroid of each of those enrollments at
every centroid bar for 1 to 3 profiles, so the attack scores meet every
value a household can use, whatever its companions. The no-face control runs
against the same enrollments.

Which shapes an entry covers. The production decision depends on the profile
count, the matchable scans of each profile and each profile's calibration
(`crates/irlume-auth/src/identity_arms.rs` lines 34-114;
`crates/irlume-auth/src/ir_assessment.rs` lines 491-515). Whether a profile
holds a calibration depends on more than its IR scan count: `calib_for`
withholds the map while untagged IR is present
(`crates/irlume-core/src/storage.rs` lines 187-199), and
`refit_profile_calib` returns early while an adapter is loaded, leaving a
stored map unrefitted (`crates/irlume-auth/src/lib.rs` lines 4656-4659). The
admitted set is therefore written as an admit list. A shape enters it only
where both an impostor arm and an attack arm reach it, and everything
outside it keeps its probes on CPU:

| Admitted shape | Impostor arms | Attack arms |
|---|---|---|
| one profile of any (n_rgb, n_ir), n_ir <= n_rgb <= 30 | the enrolled users' arms; the LFW, CBSR and Tufts single-identity arms | the attack arms on the maintainer's enrollments |
| two or three profiles of equal (k, k), k <= 30 | the Tufts households | the attack arms on household enrollments with Tufts companions |
| two or three profiles of equal (k, 0), k <= 30 | the LFW households | the attack arms on household enrollments with LFW companions and the household member |
| in every case: each profile with three or more IR scans holds a calibration fitted from exactly its current pairs, every other profile none | how every arm above fits its enrollments | the same |

That is 615 shapes: 495 of one profile and 120 of two or three (section 13).
Outside the list, among others: more than 3 profiles or more than 30
matchable scans in a profile (`MAX_PROFILES` and `MAX_SCANS_PER_PROFILE`,
`crates/irlume-core/src/storage.rs` lines 22 and 32; enrollment refuses
both, `crates/irlume-auth/src/lib.rs` lines 9614-9631 and 9729-9731, but
loading a store does not check them); profiles that differ in their numbers
of RGB or IR scans, such as a profile with IR beside one without; several
profiles whose scans carry IR only in part; a profile with three or more IR
scans and no calibration; and a stored calibration not fitted from the
profile's current pairs. With sizes free per profile there would be about
1.2e8 shapes (section 13), and no arm of this amendment reaches them; a
further amendment may add them. Today `npu_probe_admitted` checks the
placement, the IR adapter and the producer only
(`crates/irlume-auth/src/npu_probe.rs` lines 62-92); the admit list comes
with the code that implements this amendment, before any entry.

## 8. The difference record

Classification. An arm is public only when every source of the scores it
consumes, probe and template alike and for fusion both modalities, is named
in the record by a file-list digest that the validator holds for a public
copy: the two LFW copies and FairFace (section 3). The validator does not
take the writer's label for it. A public image scored against an enrolled
person's template names the private manifest as its template source, so its
arm is private whatever the writer called it. The validator also holds the
CBSR, Tufts and Oulu-CASIA digests, as private copies: an arm naming one of
them is private. A label checked against a list of private arm names would
fail open on the first mislabelled arm; a list of public digests fails
closed.

Extent of a private arm. A private arm spans every shape, threshold value
and grid point of one pairwise or decision arm, both orders included, for
one person and camera, or one corpus copy or pairing of copies, and one
class; each impostor population, modality, lighting and demographic group is
an arm of its own, since items 4 and 5 keep them apart. Without that rule a
writer could close a private arm per shape or per measured budget, the unit
the measurement code has today: one `MeasuredBudget` per population and
threshold (`crates/irlume-vision/src/onnx/gpu_evidence.rs` lines 98-115 and
129-134). A one-profile shape uses one RGB, one fallback and one dark value,
one or two centroid bars and at most 16 grid points, and the household
member's genuine RGB decision at shape n uses the single value for n
templates, so the flip total of an arm closed per shape would place an
enrolled person's genuine score within the drift of a known value. The
private arm ids therefore form a fixed list compiled into the validator and
changed only by a reviewed commit. An id is built from closed fields (the
arm's kind, its source families, the person's role, the camera category, the
modality, lighting or group, the impostor population and the class), none of
which is a number, a shape, a threshold value or a grid point. The list does
not classify: an arm's class still comes from its source digests, and an arm
they make private must carry an id from the list. The validator refuses a
private arm whose id is not on the list, or that appears twice in one
record, and the type that writes a private arm is built only from the arm's
whole plan, never from one shape or one budget.

Identity. The measurement code's identity lines name libraries by path (for
example lines 12-13 and 60-65 of the 2026-10-22 log in section 1). The
record keeps the identity as library basenames with their digests, so the
validator's refusal of any path does not push the identity out of the
validated record.

Where the record lives. The archived record stays on the project share; the
change that adds an entry cites it by digest, and git carries per-arm
aggregates only. That keeps the LFW copy's use statement ("This campaign
does not publish dataset images, pair records, or derived identity data",
its local `PROVENANCE.md`) true for the public arms too.

Public arms. The archived record holds, per threshold value and grid point,
the enumerated, excluded and measured counts and every budget field, and per
differing verdict the arm, the threshold value or grid point, the file-list
ordinals, both accept flags, both margins and the drift. A margin is the
smallest equal shift of the verdict's input cosines that flips that device's
verdict. For a verdict on one cosine (raw RGB, raw or calibrated IR, a
centroid) that is its distance to the threshold, and where verdicts differ,
`|cpu - threshold| <= |cpu - accelerator| <= d`. A composed decision (best
of n, a household, the lit arms in order, the dark best and centroid) only
grows with each of its cosines (`crates/irlume-auth/src/lib.rs` lines
1462-1464; `crates/irlume-auth/src/identity_arms.rs` lines 67-114;
`crates/irlume-auth/src/ir_assessment.rs` lines 504-515), so the same bound
holds for its equal shift. Fusion margins follow section 6.

Private arms. Nothing per comparison, per shape or per threshold value of a
private arm is archived, at any drift. The measurement code keeps each
margin as an exact two-part difference from the threshold
(`crates/irlume-vision/src/onnx/gpu_evidence.rs` lines 255-264), so one
archived margin with its threshold gives the exact CPU or accelerator score
of an identified comparison, and even without margins a difference at a
known threshold value places a score within d of it. The per-threshold
budget fields (accepts, rejects and the shifted counts, lines 130-142) over
the threshold set trace the score distribution at a spacing down to 2.4e-4
for RGB and 8.2e-5 for IR (section 13). The code already keeps the
difference table private and not printable (lines 83-97), and item 8 says no
biometric data (ADR-0022 lines 349-351).

| Archived for a private arm | Kept only on the measuring machine |
|---|---|
| enumerated, excluded and measured counts | every differing verdict, at any drift: ordinals, both accept flags, both margins |
| drift (exact two-part value) | per shape, threshold value and grid point: the verdict table (accepts, rejects, shifted counts, differences in each direction) |
| outcome: pass, fail or refused | nearest scores, and the fusion candidate count K |
| differing verdicts in each direction, summed over the arm's whole extent | the run's standard output and error |
| whether every margin lay within the drift | the recorded frames, the private manifest and the CBSR, Tufts and Oulu-CASIA images |
| SHA-256 of the local difference list | the list's random opening value |

The counts are sizes of the recording and of the populations, not scores,
and item 8 asks for run counts. The flip totals are summed over the arm's
whole extent, so that no total names a shape, a threshold value or a grid
point. The outcome says whether items 4 and 5 held at every threshold value
and grid point. The validator refuses, on any private arm, a difference
line, a per-threshold count or budget line and a nearest-score line, at any
drift, and a pass of an impostor, attack or negative private arm with any
new grant (its summed CPU-deny, accelerator-grant total above zero), since
the archived fields are all a remote reviewer sees.

The hiding digest. A difference list of an arm with few differences is a
low-entropy file: its per-threshold table follows from the archived counts,
the public threshold set and accept counts that are monotone in the
threshold, so an unsalted SHA-256 of it could be matched by guessing
candidate tables, by anyone holding the share or its pCloud backup copy. The
list therefore opens with one line, `IRLUME-EVIDENCE-LOCAL/1 NONCE value=<64
hex>`, a 256-bit value from the kernel's random source drawn for that run
and kept only in that list; the archived digest covers it. Guessing the
table then means guessing the value. The local check refuses a list whose
first line is not such a value, an all-zero value, and a value that opens
any other list on the machine. An HMAC-SHA-256 under a root-only key that
never leaves the measuring machine would serve the same end; the per-run
value needs no key management.

Refusal. Differences of private arms are listed in the local list at every
drift; the 1e-5 limit decides only whether the arm can support an entry. A
private arm with any differing verdict while its drift is above 1e-5 is
refused, and so is one that measured nothing, the no-face control excepted.
The f32 runs measured largest drifts of 5.96e-7 to 7.5e-7 (ADR-0033 lines
253-270; section 10), and a difference at more than ten times that is not
passed on a list no reviewer outside the machine can read.

Readers. The local list, with its verdict tables, stays on the measuring
machine in a root-owned file, mode 0600 in a 0700 directory, beside the
recorded frames and the private manifest, outside git, the share and any
cloud drive. Item 4's list and item 8's verdict tables for these arms are
met there, and the maintainer reviews them in place. Local code reads the
list only to check it against the archived record (the random opening value
is present, per arm and direction the listed verdicts sum to the archived
totals, every margin is within the drift, the arm measured something, the
tables give the archived outcome, and the file's SHA-256 equals the archived
digest) and prints only the result. No agent, model service, CI job or
remote reviewer reads the list, and no part of it is pasted into an issue,
pull request, chat, ledger or shared file: an agent session that read it
would send exact comparison scores of an enrolled person to its model
provider without the data ever touching git, the share or a cloud drive.
Agents receive only the runner's result lines (the harness's, the local
check's and the validator's, with the validated record's SHA-256) and the
archived fields. Root ownership also keeps user-level tools, such as a
search over the home directory or an indexing service, from reading it by
accident.

Validation before release. During a run with a private arm the measuring
process writes the archived record beside the local list, in the root-only
directory. After the local check, the record validator runs there as root,
in the same sandbox. It checks the grammar, the public or private class of
every arm, the private arm list, the refusals on private arms, and the path
and name scan, which also covers every session name of the run manifest, and
it prints one result line. Only a record it passed is copied out, with its
SHA-256, to where the archive step reads it, and the archive step checks
that digest again; a refused record stays in the root-only directory for the
maintainer. A writer bug that put a per-threshold or nearest-score line on a
private arm, the route of the 2026-10-21 share log below, therefore stops
before an agent-readable file holds it.

The console. The same holds for what the measuring process prints. A test
harness that prints to whoever started it, as the 2026-10-21 frame lanes
did, carries per-comparison data to that session: lines 14-17 of
`artifacts/irlume/2026-10-21-1053-f32-witness/ux5406s-f32-campaign/c3-frames-corpora-20261021T052245Z.log`
on the share print a nearest CPU score per recorded arm, and lines 19-22
per-threshold budget lines of the same arms (read with every digit masked
for this record; printed by `crates/irlume-vision/src/onnx/npu_tests.rs`
lines 89-95 through `gpu_tests.rs` lines 2098-2120, and `gpu_tests.rs` line
2144 with `gpu_evidence.rs` lines 129-142). A run with any private arm
therefore writes its standard output and error to a root-owned 0600 file
beside the local list, and the runner prints only the harness result line,
the local check's line and the validator's line. Whether those eight share
log lines are redacted is put to the maintainer now (AGENTS.md lines 7-10).

Statistics already published. Some committed text already carries rounded
summary statistics of the maintainer's past sessions: the live floor's
minimum and mean (`crates/irlume-core/src/lib.rs` line 93,
`docs/recognition-results/2026-08-05-buffalo-l.md` lines 35-36, and
`floor-aggregates.json`), the dark session's minimum (`lib.rs` lines
123-125, and its research record), and two per-threshold shift counts of the
f16 runs (ADR-0033 lines 242-247). This record does not repeat them. They
are not certification evidence and carry no accelerator comparison of a
certification run; the amendment's archive rule governs the record of a
certification and adds none. The rewritten RGB comment cites the anchor
runs of the 2026-08-05 record instead of restating the floor (section 2.4);
whether to coarsen the others is put to the maintainer with the log
redaction above.

## 9. Items 6 and 7

The 2026-10-21 UX5406S runs for items 6 and 7 and for the hold witness ran
in `irlume-vision`'s unit-test binary
(`target/release/deps/irlume_vision-ff82be7144f1436b`; share
`artifacts/irlume/2026-10-21-1053-ux5406s-pm/binary.path` and
`logs/suspend-20261021T133612Z/journal-retained-20261021t133612z.log` line
2, selector `gpu_retained_hw_reliability_control`; the compile lane in
`artifacts/irlume/2026-10-21-1053-f32-witness/ux5406s-f32-campaign/c1-identity-compile-20261021T052224Z.log`
line 1). Its compile lane, built from `5728309b` with the f32 configuration
(the campaign's `HOST.txt`), used `compile`, and the retained control
`compile_with_cache_observation` with the cache disabled
(`crates/irlume-vision/src/onnx/gpu_reliability_hardware_tests.rs` line 313
at `5b275141`, the HEAD in the archive's `logs/build.log` line 1); both are
test-only on main (`crates/irlume-vision/src/npu/gpu.rs` lines 1445-1454 and
1522-1523). Neither has the marker, blob discard and per-inference inventory
check of `compile_certified` (lines 1466-1514), which first appears in
`98d310c7` on 2026-10-22 (`git log -S 'fn compile_certified'`).

A suspend between the last check and the end of an inference batch discards
those outputs and rechecks the reference digest; a passing recheck after a
resume lets the accelerator answer again (`crates/irlume-vision/src/lib.rs`
lines 1236-1256, lines 969-989 at `98d310c7`). Items 6 and 7 need exactly
those events, so their runs expect suspends, record each one, count every
recheck and discard, and require every recheck to pass. The runs of items 3
to 5 refuse any of them.

Item 7 asks for cold compiles "with the cache bypassed" (ADR-0022 lines
345-346). The production compile has no bypass: `compile_certified` always
compiles into its cache's blob directory (`gpu.rs` lines 1473-1478). Item
7's cold compiles therefore start from an emptied run cache, and those runs
turn off the driver stack's own compiler cache (for the Intel compute
runtime, `NEO_CACHE_PERSISTENT`, a setting the installed `libigdrcl.so`
names), so that no compiled program carries over between them. Every other
run, item 7's warm loads included, records the driver-cache setting it ran
under, so that production does not load kernels through a cache route the
evidence never exercised; an entry holds only under that setting.

## 10. The 2026-10-22 run, an input

| Arm at 0.55 | Measured | Excluded pairs | Largest drift | Differences |
|---|---|---|---|---|
| LFW genuine (protocol) | 3,000 | not printed | 5.96e-7 | 0 |
| LFW impostor (protocol) | 3,000 | not printed | 2.83e-7 | 0 |
| FairFace Black | 1,450 | 105 | 3.58e-7 | 0 |
| FairFace East Asian | 1,477 | 72 | 3.58e-7 | 0 |
| FairFace Indian | 1,452 | 63 | 3.28e-7 | 0 |
| FairFace Latino Hispanic | 1,556 | 66 | 2.68e-7 | 0 |
| FairFace Middle Eastern | 1,153 | 55 | 3.13e-7 | 0 |
| FairFace Southeast Asian | 1,382 | 32 | 3.58e-7 | 0 |
| FairFace White | 1,922 | 162 | 4.32e-7 | 0 |

Drifts and counts from log lines 70-90 and `SUMMARY-table.md` of the archive
in section 1. Identity `1f570994` (log line 11), f32, kernel 7.2.11; 281
images without a usable aligned face (line 84); 7,762.84 s (line 94). Probes
were embedded through test-side copies of the preprocessing
(`crates/irlume-vision/src/onnx/gpu_tests.rs` lines 1822-1835), scores were
zip-sum dot products rather than `align::cosine`, and only 0.55 was judged.
It is an input, not a pass.

## 11. Cost

Embedding took 0.416 s per image, CPU and GPU with flip TTA: 7,762.84 s for
18,655 distinct images (the 7,701 images of the LFW protocol pairs and the
10,954 FairFace images, each embedded once, `gpu_tests.rs` lines 2502-2504).
Every image of the amendment's corpora is 112,740 images, about 13.0 h: both
LFW copies 26,466, FairFace 10,954, CBSR 3,940, Tufts 6,468 and Oulu-CASIA
64,912 (section 13). Scoring every ordered pair takes three 512-dimension
dot products per unordered pair (CPU with CPU, and each direction's
accelerator probe with the CPU template): about 2.7e11 multiply-adds for
both LFW copies, 1.3e10 for FairFace, 1.2e10 for CBSR, 1.6e10 for Tufts and
5.4e11 for Oulu-CASIA. The decision arms reuse those scores; households
compare stored prefix maxima, and the CBSR triples are the largest at
9.25e10 impostor decisions per order and bar.

Fusion is the largest arm by combinations and not by work. At the comparison
level, 367,754,310 RGB scores (both LFW copies and FairFace) meet 15,519,660
CBSR and 10,455,522 Tufts NIR scores: 9.55e15 combinations, and Oulu-CASIA
adds 4.13e16 within its lightings (section 13). One `fuse` call per corpus
combination would take 111 days at 1e9 calls per second. The counting of
section 6 needs, per IR class list, four accept searches and two band
searches per RGB score at each of at most 16 grid points, and four
range-wide searches: 200 passes per IR family. As merges of sorted lists
that is about 1.5e11 steps for the corpus pairings and 1.4e11 for
Oulu-CASIA, minutes on one core; as binary searches, at most 3.5e12 steps
for the corpus pairings. The decision level adds 75,413,607 RGB decision
scores per LFW copy and order with CBSR (n = 1 to 19, 5.85e13 combinations)
and 81,555,581 with Tufts (n = 1 to 30, 2.81e13). The RGB scores of both
devices in f32 take 2.94 GB, and the lane holds one family at a time. Each
candidate costs two `fuse` calls per grid point; K is counted before the
first call and recorded (for a private arm, only in its local list), and the
floor band of section 6 is estimated at a few million per IR family.

## 12. What is not established

- That the Hugging Face LFW copy equals the UMass release byte for byte.
- The subset of the June SFHQ run; SFHQ is not a certification arm.
- What the `aura-lamp` run of `floor-aggregates.json` recorded and why the
  UX5406S anchor run was repeated (section 2.4); no committed text says, and
  no claim of the amendment rests on that run.
- The CBSR mirror's identity with the CASIA release: no official checksum is
  published, and checking would mean an official download. How many CBSR
  images the production cascade can align.
- The Tufts mirror's identity with the lab's release (the mirror holds 224
  by 224 crops, `benchmarks/bench_nir_ext.py` line 13, and an uploader's
  pairing file), and that the repository's earlier Tufts figures were
  measured on it; its layout matches the benchmark scripts (section 2.5).
- Terms for Oulu-CASIA beyond research use.
- The frames of the six recordings section 7 lists as not held (the
  2026-06-30 self-test, the 2026-07-27 re-measurement, the #516 fleet banner
  runs, the 2026-08-12 flrgb session, the 2026-08-22 ViT corpus and the
  2026-08-23 dark session); the re-recordings replace them.
- How many attack frames the CPU reference aligns in IR. The FLIR attack
  bursts, which the manifest holds, showed no face detectable in IR in any
  of their 252 frames
  (`docs/research/2026-08-21-flir-public-nir-revalidation.md` lines 34-36
  and 46-48). A frame the CPU reference cannot align is left out of every
  decision it would have made (section 5), so the IR decisions of the attack
  arms rest on the attack frames that hold an IR face.
- Whether enrollments outside the admit list can be certified at full extent
  (section 7); until a further amendment adds them, their probes stay on the
  CPU.
- Whether the full extent stays within items 4 and 5 under f32 rounding, the
  fusion floors in particular (section 6). That is what the runs answer.

## 13. The counting script

Run on 2026-10-22 on the UX5406S as `python3 -I extent_counts.py` with eight
paths: the original LFW images (`~/datasets/lfw/train/images`), the
extracted Kaggle deep-funneled folder, the Kaggle deep-funneled archive (for
its listing only), the FairFace 0.25 tree (`~/datasets/fairface`), the
Kaggle CBSR folder with its two split files (file-list digest
`da3b1393...`), the CBSR copy of 2026-06-26 (for its split text only), the
Kaggle Tufts folder (`5bf7f510...`) and the Oulu-CASIA tree
(`~/datasets/oulu-casia`). It reads file names, directory and archive
listings, the CBSR split text and the Tufts pairing file, never an image.
The f32 threshold emulation rounds `log2` from f64; the Rust test of the
generated set computes the binding values. The fusion lines count
combinations and searches from the same file names, and the floor-band lines
are an estimate from the two LFW percentiles of `lfw-aura.txt` line 4, not a
measurement. The last three lines count the companions and household
enrollments of the attack arms (section 7) and print the RGB, fallback and
dark values for 31 and 90 templates. Script SHA-256
`16cf24a9234258bd35bc713647b38ffbce1958e8b910af642e2909601e300554`, output
SHA-256 `13ff0018547f4d0b8e4738cf1e43c3e991caf067eaa9c0768e30133b096d3666`.

```python
"""Extent counts for the certification-extent record (ADR-0022 amendment 2026-10-22).

Reads file names, directory listings, archive listings and split text only.
Opens no image. Run with python3 -I and these arguments, in order:
LFW_ORIG_IMAGES LFW_DFUN_DIR LFW_DFUN_ZIP FAIRFACE_DIR CBSR_DIR CBSR_OLD_DIR TUFTS_DIR OULU_DIR
"""
import csv
import math
import os
import re
import struct
import sys
import zipfile
from collections import Counter
from itertools import combinations

(lfw_dir, dfun_dir, dfun_zip, ff_dir, cbsr_dir, cbsr_old, tufts_dir,
 oulu_dir) = sys.argv[1:9]


def walk(root, exts):
    return sorted(os.path.relpath(os.path.join(r, f), root)
                  for r, _, fs in os.walk(root) for f in fs if f.lower().endswith(exts))


def lfw_identity(stem):
    # The irbench --lfw rule (crates/irlume-cli/src/main.rs:2637-2643).
    head, sep, idx = stem.rpartition("_")
    if sep and idx and all(c in "0123456789" for c in idx):
        return head
    return stem


def by_identity(names, key):
    return Counter(key(os.path.splitext(os.path.basename(n))[0]) for n in names)


def ordered(per_id):
    n = sum(per_id.values())
    gen = sum(m * (m - 1) for m in per_id.values())
    return n, gen, n * (n - 1) - gen


def single(per_id, cap, kmin=1):
    # Every n from kmin to min(cap, m - 1); genuine probes are the identity's
    # other images, impostor probes every image of every other identity.
    n_all = sum(per_id.values())
    sizes = [(m, k) for m in per_id.values() for k in range(kmin, min(cap, m - 1) + 1)]
    return (len(sizes), sum(m - k for m, k in sizes), sum(n_all - m for m, _ in sizes))


def households(sizes, n_all, cap, kmin=1):
    # Every 2- and 3-subset of the given identity sizes; equal k per member,
    # from kmin to min(cap, smallest member - 1); genuine probes are members'
    # images after their k-th, impostor probes every image outside.
    out = {}
    for r in (2, 3):
        cnt = gen = imp = 0
        for c in combinations(sizes, r):
            kmax = min(cap, min(c) - 1)
            ks = max(0, kmax - kmin + 1)
            if ks == 0:
                continue
            cnt += 1
            ksum = (kmin + kmax) * ks // 2
            gen += ks * sum(c) - r * ksum
            imp += ks * (n_all - sum(c))
        out[r] = (cnt, gen, imp)
    return out


# LFW: both copies.
orig = walk(lfw_dir, ".jpg")
dfun = walk(dfun_dir, ".jpg")
with zipfile.ZipFile(dfun_zip) as z:
    listing = z.namelist()
mac = [n for n in listing if n.startswith("__MACOSX/")]
zjpg = [n for n in listing if not n.startswith("__MACOSX/") and n.lower().endswith(".jpg")]
print("lfw-dfun zip: entries", len(listing), "__MACOSX entries", len(mac),
      "__MACOSX ._*.jpg", sum(os.path.basename(n).startswith("._") and n.lower().endswith(".jpg") for n in mac),
      "images", len(zjpg))
print("lfw-dfun folder: images", len(dfun), "AppleDouble files", sum(os.path.basename(n).startswith("._") for n in dfun),
      "same file names as the zip", Counter(map(os.path.basename, dfun)) == Counter(map(os.path.basename, zjpg)))
print("lfw-orig and lfw-dfun file names equal:",
      Counter(map(os.path.basename, orig)) == Counter(map(os.path.basename, dfun)))
for label, names in (("lfw-orig", orig), ("lfw-dfun", dfun)):
    ids = by_identity(names, lfw_identity)
    n, gen, imp = ordered(ids)
    print(label, "images", n, "identities", len(ids), "with >=2", sum(m >= 2 for m in ids.values()),
          "with >=31", sum(m >= 31 for m in ids.values()), "with >=32", sum(m >= 32 for m in ids.values()))
    print(label, "ordered genuine", gen, "ordered impostor", imp, "unordered", gen // 2, imp // 2,
          "every pair", n * (n - 1) // 2)
ids = by_identity(orig, lfw_identity)
n_lfw = sum(ids.values())
print("lfw single, per order:", single(ids, 90),
      "identities above 30 templates", sum(min(90, m - 1) > 30 for m in ids.values()))
h = households(sorted(m for m in ids.values() if m >= 31), n_lfw, 30)
print("lfw households, per order (count, genuine, impostor): pairs", h[2], "triples", h[3])

# FairFace 0.25 validation.
tot = consec = ff_images = 0
for g in sorted(d for d in os.listdir(ff_dir) if os.path.isdir(os.path.join(ff_dir, d))):
    k = sum(f.lower().endswith(".jpg") for f in os.listdir(os.path.join(ff_dir, g)))
    tot, consec, ff_images = tot + k * (k - 1), consec + k - 1, ff_images + k
    print("fairface", g, "images", k, "ordered pairs", k * (k - 1))
print("fairface ordered", tot, "unordered", tot // 2, "consecutive", consec)

# CBSR: the provenance copy (Kaggle gpreda folder).
bmps = walk(cbsr_dir, ".bmp")
cb = by_identity(bmps, lambda s: s.split("-")[0])  # irbench default key, main.rs:2645
n_cb, gen, imp = ordered(cb)
print("cbsr images", n_cb, "identities", len(cb), "per identity", sorted(set(cb.values())),
      "ordered genuine", gen, "ordered impostor", imp, "unordered impostor", imp // 2)
row = re.compile(r'^[^,\s"]+\.bmp,-?\d+,-?\d+,-?\d+,-?\d+$')
for copy, base in (("provenance copy", cbsr_dir), ("2026-06-26 copy", cbsr_old)):
    for label in ("gallery", "probe"):
        with open(os.path.join(base, f"{label}-groundtruth.txt"), encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
        print("cbsr", copy, label, "split rows", sum(bool(row.match(x)) for x in lines), "other lines",
              sum(not row.match(x) for x in lines))
P = len(cb)
print("cbsr sweep11 genuine", P * 9, "impostor", P * 9 * (P - 1))
print("cbsr release 8/12 genuine", P * 12, "impostor", P * 12 * (P - 1))
print("cbsr single, per order:", single(cb, 30))
h = households(sorted(cb.values()), n_cb, 30)
print("cbsr households, per order (count, genuine, impostor): pairs", h[2], "triples", h[3])

# Tufts: the Kaggle wahabarabo folder, TD_RGB_A and TD_NIR_A, Sets 1-4.
# Identity is the subject directory; each appears in exactly one set.
tuf = {}
for mod in ("rgb", "nir"):
    base = os.path.join(tufts_dir, f"td-{mod}-a", f"td-{mod}-a")
    names = walk(base, ".png")
    tuf[mod] = Counter(n.split(os.sep)[1] for n in names)
    sets_per_id = Counter()
    for s in os.listdir(base):
        for sid in os.listdir(os.path.join(base, s)):
            if os.path.isdir(os.path.join(base, s, sid)):
                sets_per_id[sid] += 1
    n, gen, imp = ordered(tuf[mod])
    print("tufts", mod, "images", n, "identities", len(tuf[mod]), "identities in more than one set",
          sum(v > 1 for v in sets_per_id.values()), "ordered genuine", gen, "ordered impostor", imp)
print("tufts per-identity counts equal across modalities", tuf["rgb"] == tuf["nir"])
hist = sorted(Counter(tuf["nir"].values()).items())
print("tufts images per identity (count: identities)", hist)
tid = tuf["nir"]
n_tu = sum(tid.values())
print("tufts identities with >=2", sum(m >= 2 for m in tid.values()), ">=4", sum(m >= 4 for m in tid.values()),
      ">=31", sum(m >= 31 for m in tid.values()), "largest", max(tid.values()))
with open(os.path.join(tufts_dir, "rgb_nir_fullpaths.csv"), newline="") as f:
    rows = list(csv.reader(f))


def tkey(p):
    parts = p.replace("\\", "/").split("/")
    return (parts[-3].split("Set")[-1], parts[-2], parts[-1].split("_A_", 1)[1])


pairs = sum(tkey(r[0]) == tkey(r[2]) for r in rows[1:])
print("tufts csv rows", len(rows) - 1, "rows pairing the same set, subject and file suffix", pairs)
print("tufts single (k,k), k = 1 to min(30, m - 1), per order:", single(tid, 30))
print("tufts single calibrated, k = 3 to min(30, m - 1), per order:", single(tid, 30, 3))
h = households(sorted(m for m in tid.values() if m >= 2), n_tu, 30)
print("tufts households (k,k), k = 1 up, per order (count, genuine, impostor): pairs", h[2], "triples", h[3])
h = households(sorted(m for m in tid.values() if m >= 4), n_tu, 30, 3)
print("tufts households calibrated, k = 3 up, per order: pairs", h[2], "triples", h[3])

# Oulu-CASIA NIR-VIS: NI and VL under Dark, Weak and Strong; subject P001-P080.
oroot = os.path.join(oulu_dir, "Oulu_CASIA_NIR_VIS")
oulu = {}
for mod in ("NI", "VL"):
    for light in ("Dark", "Weak", "Strong"):
        names = walk(os.path.join(oroot, mod, light), (".jpg", ".jpeg"))
        oulu[(mod, light)] = Counter(n.split(os.sep)[0] for n in names)
        n, gen, imp = ordered(oulu[(mod, light)])
        print("oulu", mod, light, "images", n, "subjects", len(oulu[(mod, light)]),
              "ordered genuine", gen, "ordered impostor", imp)
print("oulu images", sum(sum(c.values()) for c in oulu.values()))


def f32(x):
    return struct.unpack("f", struct.pack("f", x))[0]


STEP, CAP, MARGIN = f32(0.015), f32(0.10), f32(0.05)


def scaled(base, n):
    # irlume_core::scaled_threshold (crates/irlume-core/src/lib.rs:178-184)
    # in f32, with log2 rounded from f64.
    if n <= 1:
        return f32(base)
    return f32(f32(base) + min(f32(STEP * f32(math.log2(n))), CAP))


def series(top):
    rng = range(1, top + 1)
    return ([scaled(0.55, n) for n in rng], [f32(scaled(0.55, n) + MARGIN) for n in rng],
            [scaled(0.635, n) for n in rng])


def gap(values):
    v = sorted(set(values))
    return min(b - a for a, b in zip(v, v[1:]))


rgb, fallback, dark = series(90)
print("thresholds 1..90: distinct per base", len(set(rgb)), len(set(fallback)), len(set(dark)),
      "union", len(set(rgb) | set(fallback) | set(dark)),
      "smallest gap RGB %.3g, IR %.3g" % (gap(rgb), gap(fallback + dark)))
cap_n = next(n for n in range(2, 1000) if f32(STEP * f32(math.log2(n))) >= CAP)
rgb, fallback, dark = series(cap_n)
print("cap binds from", cap_n, "templates; distinct up to the cap", len(set(rgb)), len(set(fallback)),
      len(set(dark)), "union", len(set(rgb) | set(fallback) | set(dark)))

# docs/recognition-results/data/lfw-aura.txt:3-8, printed to 4 decimals (FRR)
# and 5 decimals (FAR); the all-pairs rate is genuine accepts plus impostor
# accepts over every pair.
G, I, A = 242257, 87307271, 87549528
for t, frr, far in ((0.50, 0.1798, 0.00003), (0.55, 0.2974, 0.00002)):
    lo = ((1 - frr - 5e-5) * G + (far - 5e-6) * I) / A
    hi = ((1 - frr + 5e-5) * G + (far + 5e-6) * I) / A
    print("all-pairs rate implied at %.2f: %.4g to %.4g" % (t, lo, hi))

# Fusion, comparison level. RGB families: both LFW copies (genuine and
# impostor) and FairFace 0.25 (impostor only). IR families: CBSR and Tufts
# NIR. Every pairing of an RGB and an IR family is its own arm.
lfw = ordered(ids)
cbo = ordered(cb)
tno = ordered(tid)
rgb_gen, rgb_imp = 2 * lfw[1], 2 * lfw[2] + tot
R = rgb_gen + rgb_imp
print("fusion RGB scores", R, "(genuine", rgb_gen, "impostor", rgb_imp, ") CBSR IR scores", cbo[1] + cbo[2],
      "Tufts NIR scores", tno[1] + tno[2])
allc = 0
for name, (_, ig, ii) in (("cbsr", cbo), ("tufts", tno)):
    c = (rgb_gen + rgb_imp) * (ig + ii)
    allc += c
    print("fusion with", name, "GG", rgb_gen * ig, "GI", rgb_gen * ii, "IG", rgb_imp * ig, "II", rgb_imp * ii,
          "all %.3g" % c)
print("fusion comparison-level combinations, all pairings %.3g; one fuse call each at 1e9 per second: %.0f days"
      % (allc, allc / 1e9 / 86400))
print("tufts native fusion (one combination per ordered pair of paired scans): genuine", tno[1],
      "impostor", tno[2])
oulu_steps = 0
for light in ("Dark", "Weak", "Strong"):
    v, n_ = ordered(oulu[("VL", light)]), ordered(oulu[("NI", light)])
    oulu_steps += 2 * (6 * 16 + 4) * (v[1] + v[2] + n_[1] + n_[2])
    print("oulu fusion", light, "VL scores", v[1] + v[2], "NI scores", n_[1] + n_[2],
          "combinations %.3g" % ((v[1] + v[2]) * (n_[1] + n_[2])))
print("oulu fusion combinations, three lightings %.3g; linear steps %.2g" % (
    sum(sum(ordered(oulu[("VL", l)])[1:]) * sum(ordered(oulu[("NI", l)])[1:]) for l in ("Dark", "Weak", "Strong")),
    oulu_steps))
# Per IR class list and grid point: four accept searches (CPU, CPU +d,
# CPU -d, accelerator) and two band searches; four more per IR list for the
# range-wide counts; at most 16 grid points; two IR class lists per family.
passes = 2 * (6 * 16 + 4)
steps = passes * (R + cbo[1] + cbo[2]) + passes * (R + tno[1] + tno[2])
print("passes per IR family", passes, "linear steps, both IR families %.2g" % steps,
      "binary-search steps at most %.2g" % (2 * passes * R * 24))
print("RGB scores of both devices in f32: %.2f GB" % (R * 2 * 4 / 1e9))
# Scoring: three 512-dimension dot products per unordered pair (CPU with CPU,
# and each direction's accelerator probe with the CPU template).
unord = {"lfw, both copies": 2 * n_lfw * (n_lfw - 1) // 2, "fairface": tot // 2,
         "cbsr": n_cb * (n_cb - 1) // 2, "tufts, both modalities": 2 * (n_tu * (n_tu - 1) // 2),
         "oulu, six arms": sum(sum(c.values()) * (sum(c.values()) - 1) // 2 for c in oulu.values())}
print("scoring multiply-adds:", "; ".join("%s %.2g" % (k, v * 3 * 512) for k, v in unord.items()),
      "; all %.2g" % (sum(unord.values()) * 3 * 512))


def rgb_decisions(per_id, n_all, top):
    return {n: (sum(m - n for m in per_id.values() if m > n),
                sum(n_all - m for m in per_id.values() if m > n)) for n in range(1, top + 1)}


lfw_dec = rgb_decisions(ids, n_lfw, 30)
cb_dec = rgb_decisions(cb, n_cb, 19)
tu_dec = rgb_decisions(tid, n_tu, 30)
for name, dec, top in (("cbsr", cb_dec, 19), ("tufts", tu_dec, 30)):
    r_ = sum(sum(lfw_dec[n]) for n in range(1, top + 1))
    c_ = sum(sum(lfw_dec[n]) * sum(dec[n]) for n in range(1, top + 1) if n in dec)
    print("fusion decision level with", name, "n = 1 to", top, "per LFW copy and order: RGB decisions", r_,
          "combinations %.3g" % c_)

# Enrollment shapes. One profile: 0 <= n_ir <= n_rgb <= 30, n_rgb >= 1.
one = sum(nr + 1 for nr in range(1, 31))
one_ir = sum(nr for nr in range(1, 31))
multi = 2 * 2 * 30  # two or three profiles of equal (k, k) or (k, 0), k = 1..30
print("one-profile shapes", one, "of which with IR", one_ir, "RGB only", one - one_ir,
      "; multi-profile admitted shapes", multi, "; admitted in all", one + multi,
      "; shapes with sizes free per profile", sum(one ** k for k in (1, 2, 3)))

# Floors and crossings of the shipped sigmoids (crates/irlume-core/src/fusion.rs:26-38).
A_R, B_R, A_I, B_I = 24.4708, -8.1873, 40.0120, -16.2221


def logit(p):
    return math.log(p / (1 - p))


floor = (logit(0.1) - B_R) / A_R
print("cosine at p = 0.10: RGB %.4f IR %.4f; at p = 0.50: RGB %.4f IR %.4f" % (
    floor, (logit(0.1) - B_I) / A_I, -B_R / A_R, -B_I / A_I))
# lfw-aura.txt:4 gives the impostor p99 0.219 and p99.9 0.295, so between 0.1%
# and 1% of impostor comparisons lie above the RGB floor. The density below is
# a log-linear reading between those two points, an estimate only.
k = math.log(10) / (0.295 - 0.219)
frac = 0.01 * math.exp(-k * (floor - 0.219))
within = 2 * lfw[2] * frac * k * 1e-6
print("LFW ordered impostor comparisons above the RGB floor, per copy: %d to %d; log-linear"
      " estimate %.3g of them, density %.3g per cosine unit" % (lfw[2] // 1000, lfw[2] // 100, frac, frac * k))
print("estimate within 1e-6 below the RGB floor, both LFW copies: %.0f; times CBSR genuine: %.2g;"
      " times Tufts NIR genuine: %.2g" % (within, within * cbo[1], within * tno[1]))
oulu_n = sum(sum(c.values()) for c in oulu.values())
emb = 2 * n_lfw + ff_images + n_cb + 2 * n_tu + oulu_n
print("images to embed: LFW both copies", 2 * n_lfw, "FairFace", ff_images, "CBSR", n_cb, "Tufts", 2 * n_tu,
      "Oulu", oulu_n, "all", emb, "hours at 0.416 s %.1f" % (emb * 0.416 / 3600))

# Attack arms on household enrollments. Each maintainer enrollment of shape
# (k, k) or (k, 0) is joined by one or two companion profiles of the same
# shape: for (k, k) the Tufts subjects the Tufts households of that k draw from
# (at least k + 1 images), for (k, 0) the identities of the LFW households (at
# least 31 images) and the household member, whose frames are private and not
# counted here. Household enrollments per maintainer camera and order.
tufts_c = {k: sum(m >= k + 1 for m in tid.values()) for k in range(1, 31)}
lfw_c = sum(m >= 31 for m in ids.values())
kk = sum(c + c * (c - 1) // 2 for c in tufts_c.values())
k0 = 30 * (lfw_c + lfw_c * (lfw_c - 1) // 2)
print("attack households (k, k): Tufts companions for k = 1 to 30:", [tufts_c[k] for k in range(1, 31)],
      "; enrollments:", kk)
print("attack households (k, 0): LFW companions", lfw_c, "; enrollments, k = 1 to 30, without the household member:", k0)
print("RGB, fallback and dark values for 31 and 90 templates: %.4f %.4f; %.4f %.4f; %.4f %.4f" % (
    scaled(0.55, 31), scaled(0.55, 90), f32(scaled(0.55, 31) + MARGIN), f32(scaled(0.55, 90) + MARGIN),
    scaled(0.635, 31), scaled(0.635, 90)))
```

Output, 2026-10-22, on the UX5406S copies:

```text
lfw-dfun zip: entries 43719 __MACOSX entries 24735 __MACOSX ._*.jpg 13233 images 13233
lfw-dfun folder: images 13233 AppleDouble files 0 same file names as the zip True
lfw-orig and lfw-dfun file names equal: True
lfw-orig images 13233 identities 5749 with >=2 1680 with >=31 32 with >=32 30
lfw-orig ordered genuine 484514 ordered impostor 174614542 unordered 242257 87307271 every pair 87549528
lfw-dfun images 13233 identities 5749 with >=2 1680 with >=31 32 with >=32 30
lfw-dfun ordered genuine 484514 ordered impostor 174614542 unordered 242257 87307271 every pair 87549528
lfw single, per order: (6799, 133025, 89766767) identities above 30 templates 30
lfw households, per order (count, genuine, impostor): pairs (496, 1687020, 194758740) triples (4960, 25305300, 1936845900)
fairface Black images 1556 ordered pairs 2419580
fairface East_Asian images 1550 ordered pairs 2400950
fairface Indian images 1516 ordered pairs 2296740
fairface Latino_Hispanic images 1623 ordered pairs 2632506
fairface Middle_Eastern images 1209 ordered pairs 1460472
fairface Southeast_Asian images 1415 ordered pairs 2000810
fairface White images 2085 ordered pairs 4345140
fairface ordered 17556198 unordered 8778099 consecutive 10947
cbsr images 3940 identities 197 per identity [20] ordered genuine 74860 ordered impostor 15444800 unordered impostor 7722400
cbsr provenance copy gallery split rows 1576 other lines 0
cbsr provenance copy probe split rows 2364 other lines 0
cbsr 2026-06-26 copy gallery split rows 1576 other lines 11
cbsr 2026-06-26 copy probe split rows 2364 other lines 14
cbsr sweep11 genuine 1773 impostor 347508
cbsr release 8/12 genuine 2364 impostor 463344
cbsr single, per order: (3743, 37430, 14672560)
cbsr households, per order (count, genuine, impostor): pairs (19306, 7336280, 1430574600) triples (1254890, 715287300, 92510490800)
tufts rgb images 3234 identities 110 identities in more than one set 0 ordered genuine 96162 ordered impostor 10359360
tufts nir images 3234 identities 110 identities in more than one set 0 ordered genuine 96162 ordered impostor 10359360
tufts per-identity counts equal across modalities True
tufts images per identity (count: identities) [(1, 1), (14, 1), (16, 2), (18, 5), (20, 1), (23, 1), (24, 2), (25, 1), (26, 6), (27, 42), (28, 1), (32, 2), (33, 3), (34, 4), (35, 4), (36, 34)]
tufts identities with >=2 109 >=4 109 >=31 47 largest 36
tufts csv rows 3234 rows pairing the same set, subject and file suffix 3234
tufts single (k,k), k = 1 to min(30, m - 1), per order: (2918, 47496, 9348000)
tufts single calibrated, k = 3 to min(30, m - 1), per order: (2700, 41357, 8649454)
tufts households (k,k), k = 1 up, per order (count, genuine, impostor): pairs (5886, 4959030, 465232702) triples (209934, 258999978, 15631183602)
tufts households calibrated, k = 3 up, per order: pairs (5886, 4296018, 427860382) triples (209934, 223528836, 14310691038)
oulu NI Dark images 10782 subjects 80 ordered genuine 1464038 ordered impostor 114776704
oulu NI Weak images 10834 subjects 80 ordered genuine 1482038 ordered impostor 115882684
oulu NI Strong images 10379 subjects 80 ordered genuine 1361614 ordered impostor 106351648
oulu VL Dark images 11350 subjects 80 ordered genuine 1622446 ordered impostor 127188704
oulu VL Weak images 11188 subjects 80 ordered genuine 1578716 ordered impostor 123581440
oulu VL Strong images 10379 subjects 80 ordered genuine 1372968 ordered impostor 106340294
oulu images 64912
thresholds 1..90: distinct per base 90 90 90 union 270 smallest gap RGB 0.000242, IR 8.21e-05
cap binds from 102 templates; distinct up to the cap 102 102 102 union 306
all-pairs rate implied at 0.50: 0.002294 to 0.002305
all-pairs rate implied at 0.55: 0.001959 to 0.001969
fusion RGB scores 367754310 (genuine 969028 impostor 366785282 ) CBSR IR scores 15519660 Tufts NIR scores 10455522
fusion with cbsr GG 72541436080 GI 14966443654400 IG 27457546210520 II 5664925323433600 all 5.71e+15
fusion with tufts GG 93183670536 GI 10038509902080 IG 35270806287684 II 3799660778939520 all 3.85e+15
fusion comparison-level combinations, all pairings 9.55e+15; one fuse call each at 1e9 per second: 111 days
tufts native fusion (one combination per ordered pair of paired scans): genuine 96162 impostor 10359360
oulu fusion Dark VL scores 128811150 NI scores 116240742 combinations 1.5e+16
oulu fusion Weak VL scores 125160156 NI scores 117364722 combinations 1.47e+16
oulu fusion Strong VL scores 107713262 NI scores 107713262 combinations 1.16e+16
oulu fusion combinations, three lightings 4.13e+16; linear steps 1.4e+11
passes per IR family 200 linear steps, both IR families 1.5e+11 binary-search steps at most 3.5e+12
RGB scores of both devices in f32: 2.94 GB
scoring multiply-adds: lfw, both copies 2.7e+11; fairface 1.3e+10; cbsr 1.2e+10; tufts, both modalities 1.6e+10; oulu, six arms 5.4e+11 ; all 8.5e+11
fusion decision level with cbsr n = 1 to 19 per LFW copy and order: RGB decisions 75413607 combinations 5.85e+13
fusion decision level with tufts n = 1 to 30 per LFW copy and order: RGB decisions 81555581 combinations 2.81e+13
one-profile shapes 495 of which with IR 465 RGB only 30 ; multi-profile admitted shapes 120 ; admitted in all 615 ; shapes with sizes free per profile 121532895
cosine at p = 0.10: RGB 0.2448 IR 0.3505; at p = 0.50: RGB 0.3346 IR 0.4054
LFW ordered impostor comparisons above the RGB floor, per copy: 174614 to 1746145; log-linear estimate 0.00458 of them, density 0.139 per cosine unit
estimate within 1e-6 below the RGB floor, both LFW copies: 48; times CBSR genuine: 3.6e+06; times Tufts NIR genuine: 4.7e+06
images to embed: LFW both copies 26466 FairFace 10954 CBSR 3940 Tufts 6468 Oulu 64912 all 112740 hours at 0.416 s 13.0
attack households (k, k): Tufts companions for k = 1 to 30: [109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 109, 108, 108, 106, 106, 101, 101, 100, 100, 100, 99, 97, 96, 90, 48, 47, 47, 47] ; enrollments: 149515
attack households (k, 0): LFW companions 32 ; enrollments, k = 1 to 30, without the household member: 15840
RGB, fallback and dark values for 31 and 90 templates: 0.6243 0.6474; 0.6743 0.6974; 0.7093 0.7324
```
