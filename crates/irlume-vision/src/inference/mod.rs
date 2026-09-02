// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Backend-neutral ONNX model compilation and named f32 tensor inference.

use irlume_common::{Error, Result};

#[cfg(any(test, feature = "experimental-openvino"))]
struct OpenVinoCache {
    path: std::path::PathBuf,
    state: irlume_common::InferenceCacheState,
    rebuilt: bool,
}

#[cfg(any(test, feature = "experimental-openvino"))]
impl OpenVinoCache {
    fn prepare(root: &std::path::Path, runtime_version: &str) -> Result<Self> {
        if !root.is_absolute() {
            return Err(Error::Hardware(
                "OpenVINO cache root must be absolute".into(),
            ));
        }
        let version = sanitize_runtime_version(runtime_version).ok_or_else(|| {
            Error::Hardware("OpenVINO runtime version cannot name a cache directory".into())
        })?;
        let path = root.join(version);
        let existed = path.is_dir();
        std::fs::create_dir_all(&path).map_err(|error| {
            Error::Io(format!(
                "cannot create OpenVINO cache directory {}: {error}",
                path.display()
            ))
        })?;
        let populated = existed
            && std::fs::read_dir(&path)
                .map_err(|error| Error::Io(format!("cannot read OpenVINO cache: {error}")))?
                .next()
                .is_some();
        Ok(Self {
            path,
            state: if populated {
                irlume_common::InferenceCacheState::Warm
            } else {
                irlume_common::InferenceCacheState::Cold
            },
            rebuilt: false,
        })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    #[cfg(test)]
    const fn state(&self) -> irlume_common::InferenceCacheState {
        self.state
    }

    fn status(&self, runtime_version: &str) -> irlume_common::InferenceCacheStatus {
        irlume_common::InferenceCacheStatus::new(
            self.path.to_string_lossy(),
            self.state,
            Some(runtime_version.to_owned()),
        )
    }

    fn rebuild_once(&mut self) -> Result<bool> {
        if self.rebuilt {
            return Ok(false);
        }
        let entries = std::fs::read_dir(&self.path)
            .map_err(|error| Error::Io(format!("cannot read OpenVINO cache: {error}")))?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|error| Error::Io(format!("cannot read OpenVINO cache entry: {error}")))?;
        if entries.is_empty() {
            return Ok(false);
        }
        for entry in entries {
            let path = entry.path();
            let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
                Error::Io(format!("cannot inspect OpenVINO cache entry: {error}"))
            })?;
            let result = if metadata.file_type().is_dir() && !metadata.file_type().is_symlink() {
                std::fs::remove_dir_all(&path)
            } else {
                std::fs::remove_file(&path)
            };
            result.map_err(|error| {
                Error::Io(format!("cannot clear OpenVINO cache entry: {error}"))
            })?;
        }
        self.rebuilt = true;
        self.state = irlume_common::InferenceCacheState::Rebuilt;
        Ok(true)
    }
}

#[cfg(any(test, feature = "experimental-openvino"))]
fn sanitize_runtime_version(version: &str) -> Option<String> {
    let readable: String = version
        .chars()
        .take(48)
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_') {
                character
            } else {
                '_'
            }
        })
        .collect();
    if readable
        .chars()
        .any(|character| character.is_ascii_alphanumeric())
    {
        let digest = irlume_common::sha256_hex(version.as_bytes());
        Some(format!("{readable}-{}", &digest[..12]))
    } else {
        None
    }
}

#[cfg(feature = "experimental-openvino")]
mod openvino;
#[cfg(feature = "onnx")]
mod ort;

/// One dimension required by a model tensor contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DimensionContract {
    /// The adapter must report and inference must use this exact dimension.
    Fixed(usize),
    /// The adapter must report and inference must use one declared static size.
    FixedOneOf(&'static [usize]),
    /// Metadata may be dynamic, but each inference batch must be exactly one.
    BatchOneOrDynamic,
}

/// One named f32 tensor expected by a model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TensorContract {
    pub name: &'static str,
    pub dimensions: &'static [DimensionContract],
}

impl TensorContract {
    /// Define a named f32 tensor with the given dimensions.
    pub const fn f32(name: &'static str, dimensions: &'static [DimensionContract]) -> Self {
        Self { name, dimensions }
    }
}

/// Complete named tensor contract for one ONNX model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionContract {
    pub model: &'static str,
    pub input: TensorContract,
    pub outputs: &'static [TensorContract],
}

/// Backend-neutral tensor element type reported by an adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TensorElementType {
    F32,
    I64,
    U8,
    Other,
}

/// Adapter-reported metadata for one named tensor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TensorMetadata {
    pub name: String,
    pub dimensions: Vec<Option<usize>>,
    pub element_type: TensorElementType,
}

impl TensorMetadata {
    /// Construct f32 metadata. `None` represents one dynamic dimension.
    pub fn f32(name: impl Into<String>, dimensions: Vec<Option<usize>>) -> Self {
        Self {
            name: name.into(),
            dimensions,
            element_type: TensorElementType::F32,
        }
    }
}

/// Complete adapter-reported input and output metadata for one model.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionMetadata {
    pub input: TensorMetadata,
    pub outputs: Vec<TensorMetadata>,
}

/// One borrowed named f32 input tensor.
#[derive(Clone, Copy, Debug)]
pub struct TensorInput<'a> {
    pub name: &'a str,
    pub shape: &'a [usize],
    pub values: &'a [f32],
}

/// One named f32 output whose storage is independent of the native request.
#[derive(Clone, Debug, PartialEq)]
pub struct OwnedTensor {
    pub name: String,
    pub shape: Vec<usize>,
    pub values: Vec<f32>,
}

type RunF32 = dyn for<'a> FnMut(TensorInput<'a>) -> Result<Vec<OwnedTensor>> + Send;

/// Compiled backend-neutral session for one validated model contract.
pub struct InferenceSession {
    contract: &'static SessionContract,
    input_metadata: TensorMetadata,
    run_f32: Box<RunF32>,
}

impl InferenceSession {
    /// Bind an adapter runner only after its discovered ports match the model.
    ///
    /// # Errors
    ///
    /// Returns an error if any input or output name, element type, rank, batch,
    /// or fixed dimension differs from `contract`.
    pub fn new<F>(
        contract: &'static SessionContract,
        metadata: SessionMetadata,
        run_f32: F,
    ) -> Result<Self>
    where
        F: for<'a> FnMut(TensorInput<'a>) -> Result<Vec<OwnedTensor>> + Send + 'static,
    {
        validate_session_metadata(contract, &metadata)?;
        Ok(Self {
            contract,
            input_metadata: metadata.input,
            run_f32: Box::new(run_f32),
        })
    }

    /// Return the validated backend-neutral input metadata.
    pub fn input_metadata(&self) -> &TensorMetadata {
        &self.input_metadata
    }

    /// Run one named f32 tensor and return validated owned outputs.
    ///
    /// # Errors
    ///
    /// Returns an error when the input violates the session contract, the
    /// adapter fails, or returned output names, shapes, or element counts differ
    /// from the contract.
    pub fn run_f32(&mut self, input: TensorInput<'_>) -> Result<Vec<OwnedTensor>> {
        validate_input(&self.contract.input, input)?;
        let outputs = (self.run_f32)(input)?;
        validate_outputs(self.contract.outputs, &outputs)?;
        Ok(outputs)
    }
}

pub(super) fn validate_session_metadata(
    contract: &SessionContract,
    metadata: &SessionMetadata,
) -> Result<()> {
    validate_tensor_metadata(&contract.input, &metadata.input)?;
    validate_output_metadata(contract.outputs, &metadata.outputs)
}

/// Minimal compilation seam shared by production runtimes and recording tests.
pub trait ModelCompiler: Send {
    /// Compile verified model bytes against their complete named tensor contract.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot compile the model or prove that
    /// its input and output metadata satisfy `contract`.
    fn compile(
        &mut self,
        model: &[u8],
        contract: &'static SessionContract,
    ) -> Result<InferenceSession>;

    /// Return bounded backend facts accumulated while constructing and using
    /// this compiler.
    fn diagnostics(&self) -> InferenceRuntimeDiagnostics {
        InferenceRuntimeDiagnostics::default()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InferenceRuntimeDiagnostics {
    pub ort_version: Option<String>,
    pub openvino_version: Option<String>,
    pub available_openvino_devices: Vec<String>,
    pub cache: Option<irlume_common::InferenceCacheStatus>,
}

/// Candidate-specific compiler selected by the global device resolver.
pub struct CandidateRuntime {
    compiler: Box<dyn ModelCompiler>,
}

#[cfg(feature = "onnx")]
impl CandidateRuntime {
    /// Construct the provider-free ONNX Runtime CPU compiler.
    ///
    /// # Errors
    ///
    /// Returns an error when the configured ONNX Runtime cannot be loaded or
    /// does not provide the API level required by the pinned `ort` crate.
    pub fn ort_cpu() -> Result<Self> {
        Ok(Self {
            compiler: Box::new(ort::OrtCompiler::new()?),
        })
    }
}

#[cfg(feature = "experimental-openvino")]
impl CandidateRuntime {
    /// Construct a runtime-linked direct OpenVINO compiler for one exact device.
    ///
    /// # Errors
    ///
    /// Returns an error when the OpenVINO runtime is absent, the device is not
    /// available, or the cache path cannot be represented for the C API.
    pub fn openvino(
        device: irlume_common::CandidateDevice,
        cache_dir: impl AsRef<std::path::Path>,
    ) -> Result<Self> {
        Ok(Self {
            compiler: Box::new(openvino::OpenVinoCompiler::new(device, cache_dir.as_ref())?),
        })
    }
}

impl ModelCompiler for CandidateRuntime {
    fn compile(
        &mut self,
        model: &[u8],
        contract: &'static SessionContract,
    ) -> Result<InferenceSession> {
        self.compiler.compile(model, contract)
    }

    fn diagnostics(&self) -> InferenceRuntimeDiagnostics {
        self.compiler.diagnostics()
    }
}

impl CandidateRuntime {
    /// Return share-safe runtime and cache facts for the selected candidate.
    pub fn diagnostics(&self) -> InferenceRuntimeDiagnostics {
        self.compiler.diagnostics()
    }
}

fn validate_output_metadata(
    contracts: &[TensorContract],
    metadata: &[TensorMetadata],
) -> Result<()> {
    if contracts.len() != metadata.len() || has_duplicate_names(metadata.iter().map(|m| &m.name)) {
        return Err(contract_error());
    }
    for contract in contracts {
        let Some(output) = metadata.iter().find(|output| output.name == contract.name) else {
            return Err(contract_error());
        };
        validate_tensor_metadata(contract, output)?;
    }
    Ok(())
}

fn validate_tensor_metadata(contract: &TensorContract, metadata: &TensorMetadata) -> Result<()> {
    if metadata.name != contract.name
        || metadata.element_type != TensorElementType::F32
        || metadata.dimensions.len() != contract.dimensions.len()
    {
        return Err(contract_error());
    }
    for (expected, actual) in contract.dimensions.iter().zip(&metadata.dimensions) {
        match (expected, actual) {
            (DimensionContract::Fixed(expected), Some(actual)) if expected == actual => {}
            (DimensionContract::FixedOneOf(expected), Some(actual))
                if expected.contains(actual) => {}
            (DimensionContract::BatchOneOrDynamic, None | Some(1)) => {}
            _ => return Err(contract_error()),
        }
    }
    Ok(())
}

fn validate_input(contract: &TensorContract, input: TensorInput<'_>) -> Result<()> {
    if input.name != contract.name || !shape_matches(contract.dimensions, input.shape) {
        return Err(contract_error());
    }
    if checked_element_count(input.shape) != Some(input.values.len()) {
        return Err(contract_error());
    }
    Ok(())
}

fn validate_outputs(contracts: &[TensorContract], outputs: &[OwnedTensor]) -> Result<()> {
    if contracts.len() != outputs.len() || has_duplicate_names(outputs.iter().map(|o| &o.name)) {
        return Err(contract_error());
    }
    for contract in contracts {
        let Some(output) = outputs.iter().find(|output| output.name == contract.name) else {
            return Err(contract_error());
        };
        if !shape_matches(contract.dimensions, &output.shape)
            || checked_element_count(&output.shape) != Some(output.values.len())
        {
            return Err(contract_error());
        }
    }
    Ok(())
}

fn shape_matches(contract: &[DimensionContract], shape: &[usize]) -> bool {
    contract.len() == shape.len()
        && contract
            .iter()
            .zip(shape)
            .all(|(expected, actual)| match expected {
                DimensionContract::Fixed(expected) => expected == actual,
                DimensionContract::FixedOneOf(expected) => expected.contains(actual),
                DimensionContract::BatchOneOrDynamic => *actual == 1,
            })
}

fn checked_element_count(shape: &[usize]) -> Option<usize> {
    shape
        .iter()
        .try_fold(1usize, |count, dimension| count.checked_mul(*dimension))
}

fn has_duplicate_names<'a>(mut names: impl Iterator<Item = &'a String>) -> bool {
    let mut seen = std::collections::HashSet::new();
    names.any(|name| !seen.insert(name))
}

fn contract_error() -> Error {
    Error::Protocol("inference tensor contract mismatch".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use DimensionContract::{BatchOneOrDynamic, Fixed, FixedOneOf};

    #[test]
    fn openvino_cache_is_versioned_and_distinguishes_clean_warm_and_changed_runtime() {
        let root = std::env::temp_dir().join(format!(
            "irlume-versioned-cache-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);

        let cold = OpenVinoCache::prepare(&root, "2026.2.0-build/releases/2026/2").unwrap();
        assert_eq!(cold.state(), irlume_common::InferenceCacheState::Cold);
        assert!(cold
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("2026.2.0-build_releases_2026_2-"));
        let status = cold.status("2026.2.0-build/releases/2026/2");
        assert_eq!(status.root, cold.path().to_string_lossy());
        assert_eq!(status.state, irlume_common::InferenceCacheState::Cold);
        assert_eq!(
            status.runtime_version.as_deref(),
            Some("2026.2.0-build/releases/2026/2")
        );
        std::fs::write(cold.path().join("compiled.blob"), b"cache").unwrap();

        let warm = OpenVinoCache::prepare(&root, "2026.2.0-build/releases/2026/2").unwrap();
        assert_eq!(warm.state(), irlume_common::InferenceCacheState::Warm);
        let changed = OpenVinoCache::prepare(&root, "2026.3.0").unwrap();
        assert_eq!(changed.state(), irlume_common::InferenceCacheState::Cold);
        assert_ne!(changed.path(), warm.path());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn openvino_cache_version_names_do_not_alias_after_sanitizing_or_truncation() {
        assert_ne!(
            sanitize_runtime_version("2026/2"),
            sanitize_runtime_version("2026_2")
        );
        assert_ne!(
            sanitize_runtime_version(&format!("{}-a", "x".repeat(80))),
            sanitize_runtime_version(&format!("{}-b", "x".repeat(80)))
        );
    }

    #[test]
    fn openvino_cache_rebuild_is_bounded_to_one_clear() {
        let root =
            std::env::temp_dir().join(format!("irlume-cache-rebuild-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let mut cache = OpenVinoCache::prepare(&root, "2026.2.0").unwrap();
        std::fs::create_dir(cache.path().join("nested")).unwrap();
        std::fs::write(cache.path().join("nested/corrupt.blob"), b"bad").unwrap();

        assert!(cache.rebuild_once().unwrap());
        assert_eq!(cache.state(), irlume_common::InferenceCacheState::Rebuilt);
        assert_eq!(std::fs::read_dir(cache.path()).unwrap().count(), 0);
        std::fs::write(cache.path().join("second.blob"), b"keep").unwrap();
        assert!(!cache.rebuild_once().unwrap());
        assert!(cache.path().join("second.blob").exists());

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn openvino_cache_refuses_relative_empty_and_uncreatable_roots() {
        assert!(OpenVinoCache::prepare(std::path::Path::new("relative"), "2026.2.0").is_err());
        assert!(OpenVinoCache::prepare(std::path::Path::new("/tmp"), "///").is_err());

        let parent =
            std::env::temp_dir().join(format!("irlume-cache-file-parent-{}", std::process::id()));
        let _ = std::fs::remove_file(&parent);
        std::fs::write(&parent, b"not a directory").unwrap();
        assert!(OpenVinoCache::prepare(&parent, "2026.2.0").is_err());
        let _ = std::fs::remove_file(parent);
    }

    static AURAFACE_OUTPUTS: [TensorContract; 1] = [TensorContract::f32(
        "1333",
        &[BatchOneOrDynamic, Fixed(512)],
    )];
    static AURAFACE: SessionContract = SessionContract {
        model: "auraface",
        input: TensorContract::f32(
            "data",
            &[BatchOneOrDynamic, Fixed(3), Fixed(112), Fixed(112)],
        ),
        outputs: &AURAFACE_OUTPUTS,
    };

    fn valid_metadata() -> SessionMetadata {
        SessionMetadata {
            input: TensorMetadata::f32("data", vec![None, Some(3), Some(112), Some(112)]),
            outputs: vec![TensorMetadata::f32("1333", vec![None, Some(512)])],
        }
    }

    fn valid_output() -> Vec<OwnedTensor> {
        vec![OwnedTensor {
            name: "1333".into(),
            shape: vec![1, 512],
            values: vec![0.25; 512],
        }]
    }

    fn session_with_metadata(metadata: SessionMetadata) -> irlume_common::Result<InferenceSession> {
        InferenceSession::new(&AURAFACE, metadata, |_| Ok(valid_output()))
    }

    #[test]
    fn adapter_metadata_must_match_the_complete_f32_contract() {
        assert!(session_with_metadata(valid_metadata()).is_ok());

        let mut wrong_name = valid_metadata();
        wrong_name.input.name = "input".into();
        assert!(session_with_metadata(wrong_name).is_err());

        let mut wrong_rank = valid_metadata();
        wrong_rank.input.dimensions.pop();
        assert!(session_with_metadata(wrong_rank).is_err());

        let mut wrong_fixed_dimension = valid_metadata();
        wrong_fixed_dimension.input.dimensions[1] = Some(4);
        assert!(session_with_metadata(wrong_fixed_dimension).is_err());

        let mut wrong_batch = valid_metadata();
        wrong_batch.input.dimensions[0] = Some(2);
        assert!(session_with_metadata(wrong_batch).is_err());

        let mut missing_output = valid_metadata();
        missing_output.outputs.clear();
        assert!(session_with_metadata(missing_output).is_err());

        let mut duplicate_output = valid_metadata();
        duplicate_output
            .outputs
            .push(duplicate_output.outputs[0].clone());
        assert!(session_with_metadata(duplicate_output).is_err());

        let mut wrong_output_shape = valid_metadata();
        wrong_output_shape.outputs[0].dimensions[1] = Some(256);
        assert!(session_with_metadata(wrong_output_shape).is_err());

        let mut non_f32 = valid_metadata();
        non_f32.input.element_type = TensorElementType::I64;
        assert!(session_with_metadata(non_f32).is_err());

        let mut non_f32_output = valid_metadata();
        non_f32_output.outputs[0].element_type = TensorElementType::U8;
        assert!(session_with_metadata(non_f32_output).is_err());
    }

    #[test]
    fn inputs_and_returned_outputs_are_validated_and_owned() {
        struct FakeRequest {
            output: Vec<f32>,
        }

        let mut session = InferenceSession::new(&AURAFACE, valid_metadata(), |_| {
            let request = FakeRequest {
                output: vec![0.25; 512],
            };
            let output = OwnedTensor {
                name: "1333".into(),
                shape: vec![1, 512],
                values: request.output.clone(),
            };
            drop(request);
            Ok(vec![output])
        })
        .unwrap();
        let values = vec![0.5; 3 * 112 * 112];

        for bad in [
            TensorInput {
                name: "input",
                shape: &[1, 3, 112, 112],
                values: &values,
            },
            TensorInput {
                name: "data",
                shape: &[1, 3, 112],
                values: &values,
            },
            TensorInput {
                name: "data",
                shape: &[1, 4, 112, 112],
                values: &values,
            },
            TensorInput {
                name: "data",
                shape: &[2, 3, 112, 112],
                values: &values,
            },
            TensorInput {
                name: "data",
                shape: &[1, 3, 112, 112],
                values: &values[..values.len() - 1],
            },
        ] {
            assert!(session.run_f32(bad).is_err());
        }

        let output = session
            .run_f32(TensorInput {
                name: "data",
                shape: &[1, 3, 112, 112],
                values: &values,
            })
            .unwrap();
        assert_eq!(output[0].values, vec![0.25; 512]);
    }

    #[test]
    fn runtime_outputs_reject_missing_duplicate_and_misshaped_names() {
        let values = vec![0.5; 3 * 112 * 112];
        let input = || TensorInput {
            name: "data",
            shape: &[1, 3, 112, 112],
            values: &values,
        };

        for outputs in [
            Vec::new(),
            vec![valid_output().remove(0), valid_output().remove(0)],
            vec![OwnedTensor {
                name: "wrong".into(),
                shape: vec![1, 512],
                values: vec![0.0; 512],
            }],
            vec![OwnedTensor {
                name: "1333".into(),
                shape: vec![1, 256],
                values: vec![0.0; 256],
            }],
        ] {
            let mut outputs = Some(outputs);
            let mut session = InferenceSession::new(&AURAFACE, valid_metadata(), move |_| {
                Ok(outputs.take().unwrap())
            })
            .unwrap();
            assert!(session.run_f32(input()).is_err());
        }
    }

    #[derive(Default)]
    struct RecordingCompiler {
        model_len: usize,
        contract_model: Option<&'static str>,
    }

    impl ModelCompiler for RecordingCompiler {
        fn compile(
            &mut self,
            model: &[u8],
            contract: &'static SessionContract,
        ) -> irlume_common::Result<InferenceSession> {
            self.model_len = model.len();
            self.contract_model = Some(contract.model);
            InferenceSession::new(contract, valid_metadata(), |_| Ok(valid_output()))
        }
    }

    #[test]
    fn model_compiler_seam_carries_only_bytes_and_contracts() {
        let mut compiler = RecordingCompiler::default();
        let mut session = compiler.compile(b"model", &AURAFACE).unwrap();
        assert_eq!(compiler.model_len, 5);
        assert_eq!(compiler.contract_model, Some("auraface"));

        let values = vec![0.5; 3 * 112 * 112];
        let outputs = session
            .run_f32(TensorInput {
                name: "data",
                shape: &[1, 3, 112, 112],
                values: &values,
            })
            .unwrap();
        assert_eq!(outputs[0].name, "1333");
    }

    #[test]
    fn fixed_one_of_dimensions_accept_only_declared_static_sizes() {
        static OUTPUTS: [TensorContract; 1] = [TensorContract::f32(
            "landmarks",
            &[Fixed(1), Fixed(1), FixedOneOf(&[1404, 1434])],
        )];
        static CONTRACT: SessionContract = SessionContract {
            model: "facemesh",
            input: TensorContract::f32(
                "image",
                &[
                    BatchOneOrDynamic,
                    FixedOneOf(&[192, 256]),
                    FixedOneOf(&[192, 256]),
                    Fixed(3),
                ],
            ),
            outputs: &OUTPUTS,
        };
        let metadata = |side: usize, points: usize| SessionMetadata {
            input: TensorMetadata::f32("image", vec![None, Some(side), Some(side), Some(3)]),
            outputs: vec![TensorMetadata::f32(
                "landmarks",
                vec![Some(1), Some(1), Some(points * 3)],
            )],
        };

        let session = InferenceSession::new(&CONTRACT, metadata(256, 478), |_| unreachable!())
            .expect("declared dimensions");
        assert_eq!(session.input_metadata().dimensions[1], Some(256));
        assert!(InferenceSession::new(&CONTRACT, metadata(224, 478), |_| unreachable!()).is_err());
        assert!(InferenceSession::new(&CONTRACT, metadata(256, 500), |_| unreachable!()).is_err());
    }
}
