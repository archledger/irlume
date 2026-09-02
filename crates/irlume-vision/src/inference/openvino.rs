// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Runtime-linked direct OpenVINO adapter for explicit NPU or GPU execution.

use super::{
    validate_session_metadata, DimensionContract, InferenceRuntimeDiagnostics, InferenceSession,
    ModelCompiler, OpenVinoCache, OwnedTensor, SessionContract, SessionMetadata, TensorContract,
    TensorElementType, TensorMetadata,
};
use irlume_common::{CandidateDevice, Error, Result};
use openvino::{
    Core, DeviceType, ElementType, Model, PartialShape, PropertyKey, RwPropertyKey, Shape, Tensor,
};
use std::collections::HashSet;
use std::path::Path;

pub(super) struct OpenVinoCompiler {
    core: Core,
    device: CandidateDevice,
    device_type: DeviceType<'static>,
    cache: OpenVinoCache,
    runtime_version: String,
    available_devices: Vec<String>,
}

impl OpenVinoCompiler {
    pub(super) fn new(device: CandidateDevice, cache_dir: &Path) -> Result<Self> {
        catch_binding(|| {
            let device_type = explicit_device(device)?;
            let mut core = load_core_with(Core::new)?;
            let runtime_version = openvino::version().build_number;
            let cache = OpenVinoCache::prepare(cache_dir, &runtime_version)?;
            let available = sanitize_devices(
                core.available_devices()
                    .map_err(ov_error)?
                    .iter()
                    .map(AsRef::<str>::as_ref),
            );
            let expected = device_type.as_ref();
            if !has_available_device(device, &available) {
                return Err(ov_error(format!(
                    "requested {expected} is unavailable; available devices: {}",
                    available.join(", ")
                )));
            }
            let cache_dir = cache
                .path()
                .to_str()
                .ok_or_else(|| ov_error("cache path is not UTF-8"))?;
            core.set_property(&device_type, &RwPropertyKey::CacheDir, cache_dir)
                .map_err(ov_error)?;
            Ok(Self {
                core,
                device,
                device_type,
                cache,
                runtime_version,
                available_devices: available,
            })
        })
    }
}

impl ModelCompiler for OpenVinoCompiler {
    fn compile(
        &mut self,
        model_bytes: &[u8],
        contract: &'static SessionContract,
    ) -> Result<InferenceSession> {
        catch_binding(|| {
            let mut model = self
                .core
                .read_model_from_buffer(model_bytes, None)
                .map_err(ov_error)?;
            let original_metadata = model_metadata(&model)?;
            validate_original_metadata(contract, &original_metadata)?;

            let input_shape = concrete_shape(&contract.input, &original_metadata.input)?;
            if original_metadata
                .input
                .dimensions
                .iter()
                .any(Option::is_none)
            {
                let dimensions = input_shape
                    .iter()
                    .map(|dimension| i64::try_from(*dimension).map_err(ov_error))
                    .collect::<Result<Vec<_>>>()?;
                let shape = PartialShape::new_static(dimensions.len() as i64, &dimensions)
                    .map_err(ov_error)?;
                model
                    .reshape_input_by_name(contract.input.name, &shape)
                    .map_err(ov_error)?;
            }

            let mut compiled = match self.core.compile_model(&model, self.device_type.to_owned()) {
                Ok(compiled) => compiled,
                Err(_first_error) if self.cache.rebuild_once()? => self
                    .core
                    .compile_model(&model, self.device_type.to_owned())
                    .map_err(ov_error)?,
                Err(error) => return Err(ov_error(error)),
            };
            let assignment = compiled
                .get_property(&PropertyKey::Other("EXECUTION_DEVICES".into()))
                .map_err(ov_error)?;
            validate_execution_devices(self.device, &assignment)?;

            let compiled_metadata = compiled_metadata(&compiled)?;
            validate_session_metadata(contract, &compiled_metadata)?;
            let mut request = compiled.create_infer_request().map_err(ov_error)?;
            let output_names: Vec<&'static str> =
                contract.outputs.iter().map(|output| output.name).collect();

            InferenceSession::new(contract, compiled_metadata, move |input| {
                let _keep_compiled_alive = &compiled;
                catch_binding(|| {
                    let dimensions = input
                        .shape
                        .iter()
                        .map(|dimension| i64::try_from(*dimension).map_err(ov_error))
                        .collect::<Result<Vec<_>>>()?;
                    let shape = Shape::new(&dimensions).map_err(ov_error)?;
                    let mut tensor = Tensor::new(ElementType::F32, &shape).map_err(ov_error)?;
                    let target = tensor.get_data_mut::<f32>().map_err(ov_error)?;
                    if target.len() != input.values.len() {
                        return Err(ov_error("OpenVINO input element count changed"));
                    }
                    target.copy_from_slice(input.values);
                    request.set_tensor(input.name, &tensor).map_err(ov_error)?;
                    request.infer().map_err(ov_error)?;

                    output_names
                        .iter()
                        .map(|name| {
                            let tensor = request.get_tensor(name).map_err(ov_error)?;
                            if tensor.get_element_type().map_err(ov_error)? != ElementType::F32 {
                                return Err(ov_error("OpenVINO returned a non-f32 output"));
                            }
                            let shape = tensor
                                .get_shape()
                                .map_err(ov_error)?
                                .get_dimensions()
                                .iter()
                                .map(|dimension| usize::try_from(*dimension).map_err(ov_error))
                                .collect::<Result<Vec<_>>>()?;
                            let values = tensor.get_data::<f32>().map_err(ov_error)?.to_vec();
                            Ok(OwnedTensor {
                                name: (*name).into(),
                                shape,
                                values,
                            })
                        })
                        .collect()
                })
            })
        })
    }

    fn diagnostics(&self) -> InferenceRuntimeDiagnostics {
        InferenceRuntimeDiagnostics {
            ort_version: None,
            openvino_version: Some(self.runtime_version.clone()),
            available_openvino_devices: self.available_devices.clone(),
            cache: Some(self.cache.status(&self.runtime_version)),
        }
    }
}

fn validate_original_metadata(
    contract: &SessionContract,
    metadata: &SessionMetadata,
) -> Result<()> {
    let mut normalized = metadata.clone();
    if metadata.input.dimensions.first() == Some(&None) {
        for output_contract in contract.outputs {
            let expected_batch = output_contract.dimensions.first();
            if !matches!(
                expected_batch,
                Some(DimensionContract::Fixed(1) | DimensionContract::BatchOneOrDynamic)
            ) {
                continue;
            }
            if let Some(output) = normalized
                .outputs
                .iter_mut()
                .find(|output| output.name == output_contract.name)
            {
                if output.dimensions.first() == Some(&None) {
                    output.dimensions[0] = Some(1);
                }
            }
        }
    }
    validate_session_metadata(contract, &normalized)
}

fn model_metadata(model: &Model) -> Result<SessionMetadata> {
    if model.get_inputs_len().map_err(ov_error)? != 1 {
        return Err(ov_error("OpenVINO model must have exactly one input"));
    }
    let input = node_metadata(&model.get_input_by_index(0).map_err(ov_error)?)?;
    let outputs = (0..model.get_outputs_len().map_err(ov_error)?)
        .map(|index| node_metadata(&model.get_output_by_index(index).map_err(ov_error)?))
        .collect::<Result<Vec<_>>>()?;
    Ok(SessionMetadata { input, outputs })
}

fn compiled_metadata(compiled: &openvino::CompiledModel) -> Result<SessionMetadata> {
    if compiled.get_input_size().map_err(ov_error)? != 1 {
        return Err(ov_error(
            "compiled OpenVINO model must have exactly one input",
        ));
    }
    let input = node_metadata(&compiled.get_input_by_index(0).map_err(ov_error)?)?;
    let outputs = (0..compiled.get_output_size().map_err(ov_error)?)
        .map(|index| node_metadata(&compiled.get_output_by_index(index).map_err(ov_error)?))
        .collect::<Result<Vec<_>>>()?;
    Ok(SessionMetadata { input, outputs })
}

fn node_metadata(node: &openvino::Node) -> Result<TensorMetadata> {
    let shape = node.get_partial_shape().map_err(ov_error)?;
    let rank = shape.get_rank();
    if rank.get_min() != rank.get_max() || rank.get_min() < 0 {
        return Err(ov_error("OpenVINO port has dynamic rank"));
    }
    let dimensions = shape
        .get_dimensions()
        .iter()
        .map(|dimension| {
            if dimension.is_dynamic() {
                None
            } else {
                usize::try_from(dimension.get_min()).ok()
            }
        })
        .collect();
    let element_type = match node.get_element_type().map_err(ov_error)? {
        ElementType::F32 => TensorElementType::F32,
        ElementType::I64 => TensorElementType::I64,
        ElementType::U8 => TensorElementType::U8,
        _ => TensorElementType::Other,
    };
    Ok(TensorMetadata {
        name: node.get_name().map_err(ov_error)?,
        dimensions,
        element_type,
    })
}

fn concrete_shape(contract: &TensorContract, metadata: &TensorMetadata) -> Result<Vec<usize>> {
    if contract.dimensions.len() != metadata.dimensions.len() {
        return Err(ov_error("OpenVINO input rank differs from its contract"));
    }
    contract
        .dimensions
        .iter()
        .zip(&metadata.dimensions)
        .enumerate()
        .map(
            |(index, (contract, actual))| match (index, contract, actual) {
                (0, DimensionContract::BatchOneOrDynamic, None | Some(1)) => Ok(1),
                (_, DimensionContract::Fixed(expected), Some(actual)) if expected == actual => {
                    Ok(*actual)
                }
                (_, DimensionContract::FixedOneOf(expected), Some(actual))
                    if expected.contains(actual) =>
                {
                    Ok(*actual)
                }
                (_, _, None) => Err(ov_error("only the batch dimension may be dynamic")),
                _ => Err(ov_error("OpenVINO input shape differs from its contract")),
            },
        )
        .collect()
}

fn sanitize_devices(devices: impl IntoIterator<Item = impl AsRef<str>>) -> Vec<String> {
    let mut seen = HashSet::new();
    devices
        .into_iter()
        .map(|device| device.as_ref().trim().to_owned())
        .filter(|device| !device.is_empty() && seen.insert(device.clone()))
        .take(irlume_common::MAX_AVAILABLE_INFERENCE_DEVICES)
        .collect()
}

fn has_available_device(device: CandidateDevice, available: &[String]) -> bool {
    let prefix = match device {
        CandidateDevice::Npu => "NPU",
        CandidateDevice::Gpu => "GPU",
        CandidateDevice::Cpu => return false,
    };
    available.iter().any(|name| {
        name == prefix
            || name
                .strip_prefix(prefix)
                .is_some_and(|tail| tail.starts_with('.'))
    })
}

fn validate_execution_devices(device: CandidateDevice, assignment: &str) -> Result<()> {
    let expected = explicit_device(device)?.as_ref().to_owned();
    if assignment.trim() == expected {
        Ok(())
    } else {
        Err(ov_error(format!(
            "OpenVINO assigned {}, expected {expected}",
            assignment.trim()
        )))
    }
}

fn explicit_device(device: CandidateDevice) -> Result<DeviceType<'static>> {
    match device {
        CandidateDevice::Npu => Ok(DeviceType::NPU),
        CandidateDevice::Gpu => Ok(DeviceType::GPU),
        CandidateDevice::Cpu => Err(ov_error("direct OpenVINO CPU is not a candidate")),
    }
}

fn load_core_with<E: std::fmt::Display>(
    loader: impl FnOnce() -> std::result::Result<Core, E>,
) -> Result<Core> {
    loader().map_err(ov_error)
}

fn catch_binding<T>(operation: impl FnOnce() -> Result<T>) -> Result<T> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
        .unwrap_or_else(|_| Err(ov_error("OpenVINO binding panicked on runtime metadata")))
}

fn ov_error(error: impl std::fmt::Display) -> Error {
    Error::Hardware(format!("openvino: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::{CandidateRuntime, DimensionContract, TensorContract, TensorMetadata};
    use crate::model_input::{
        ArcFaceInput, BlazeFaceInput, CanonicalGreyView, CanonicalRgbView, DetectorInput,
        FlirIrPadInput, VitRgbPadInput,
    };
    use crate::{BlazeRescue, Detector, Embedder, FaceMesh, PadIr, PadVit};
    use irlume_common::CandidateDevice::{Gpu, Npu};

    #[test]
    fn runtime_absence_and_binding_panics_are_errors() {
        assert!(
            load_core_with(|| -> std::result::Result<Core, &str> { Err("runtime absent") })
                .is_err()
        );
        assert!(catch_binding(|| -> irlume_common::Result<()> {
            panic!("unknown runtime metadata")
        })
        .is_err());
    }

    #[test]
    #[ignore = "hosted CI gate requires OpenVINO to be absent"]
    fn hosted_runtime_absence_is_a_recoverable_candidate_error() {
        let cache = std::env::temp_dir().join(format!(
            "irlume-openvino-absence-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&cache);

        assert!(CandidateRuntime::openvino(Npu, &cache).is_err());
        assert!(!cache.exists());
    }

    #[test]
    fn available_devices_are_sanitized_and_assignment_must_be_exact() {
        assert_eq!(
            sanitize_devices([" NPU ", "GPU.0", "", "NPU"]),
            vec!["NPU", "GPU.0"]
        );
        assert!(has_available_device(Npu, &["NPU".into(), "GPU.0".into()]));
        assert!(has_available_device(Gpu, &["NPU".into(), "GPU.0".into()]));
        assert!(validate_execution_devices(Npu, "CPU").is_err());
        assert!(validate_execution_devices(Npu, "NPU").is_ok());
        assert!(validate_execution_devices(Gpu, "GPU").is_ok());
        assert!(validate_execution_devices(Gpu, "GPU.0").is_err());
    }

    #[test]
    fn only_dynamic_batch_may_be_reshaped_to_one() {
        let batch_dynamic = TensorContract::f32(
            "data",
            &[
                DimensionContract::BatchOneOrDynamic,
                DimensionContract::Fixed(3),
                DimensionContract::Fixed(112),
                DimensionContract::Fixed(112),
            ],
        );
        let metadata = TensorMetadata::f32("data", vec![None, Some(3), Some(112), Some(112)]);
        assert_eq!(
            concrete_shape(&batch_dynamic, &metadata).unwrap(),
            [1, 3, 112, 112]
        );

        let non_batch_dynamic =
            TensorMetadata::f32("data", vec![Some(1), Some(3), None, Some(112)]);
        assert!(concrete_shape(&batch_dynamic, &non_batch_dynamic).is_err());
    }

    #[test]
    fn dynamic_output_batch_is_allowed_only_before_dynamic_input_reshape() {
        static OUTPUTS: &[TensorContract] = &[TensorContract::f32(
            "embedding",
            &[DimensionContract::Fixed(1), DimensionContract::Fixed(512)],
        )];
        static CONTRACT: SessionContract = SessionContract {
            model: "dynamic-batch",
            input: TensorContract::f32(
                "data",
                &[
                    DimensionContract::BatchOneOrDynamic,
                    DimensionContract::Fixed(3),
                    DimensionContract::Fixed(112),
                    DimensionContract::Fixed(112),
                ],
            ),
            outputs: OUTPUTS,
        };
        let metadata = SessionMetadata {
            input: TensorMetadata::f32("data", vec![None, Some(3), Some(112), Some(112)]),
            outputs: vec![TensorMetadata::f32("embedding", vec![None, Some(512)])],
        };

        assert!(validate_session_metadata(&CONTRACT, &metadata).is_err());
        assert!(validate_original_metadata(&CONTRACT, &metadata).is_ok());

        let mut static_input = metadata;
        static_input.input.dimensions[0] = Some(1);
        assert!(validate_original_metadata(&CONTRACT, &static_input).is_err());
    }

    #[test]
    #[ignore = "requires the qualified OpenVINO/NPU stack and explicit hardware authorization"]
    fn every_manifest_onnx_model_runs_deterministically_on_exact_npu() {
        struct CacheDir(std::path::PathBuf);
        impl Drop for CacheDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let model_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../models");
        let manifest = std::fs::read_to_string(model_dir.join("SHA256SUMS")).unwrap();
        let onnx_names: Vec<&str> = manifest
            .lines()
            .filter_map(|line| line.split_whitespace().nth(1))
            .filter(|name| name.ends_with(".onnx"))
            .collect();
        assert_eq!(
            onnx_names,
            [
                "face_detection_yunet_2023mar.onnx",
                "face_landmark.onnx",
                "glintr100.onnx",
                "blaze_face_short_range.onnx",
                "liveness_vit.onnx",
                "flir.onnx",
            ],
            "every manifest ONNX entry must be explicitly covered"
        );
        let read = |name: &str| std::fs::read(model_dir.join(name)).unwrap();
        let cache = CacheDir(
            std::env::temp_dir().join(format!("irlume-openvino-npu-test-{}", std::process::id())),
        );
        std::fs::create_dir(&cache.0).unwrap();
        let mut runtime = CandidateRuntime::openvino(Npu, &cache.0).unwrap();

        let mut detector = Detector::load_from_memory_with_runtime(
            &mut runtime,
            &read("face_detection_yunet_2023mar.onnx"),
        )
        .unwrap();
        let mut mesh =
            FaceMesh::load_from_memory_with_runtime(&mut runtime, &read("face_landmark.onnx"))
                .unwrap();
        let mut embedder =
            Embedder::load_from_memory_with_runtime(&mut runtime, &read("glintr100.onnx")).unwrap();
        let mut blaze = BlazeRescue::load_from_memory_with_runtime(
            &mut runtime,
            &read("blaze_face_short_range.onnx"),
        )
        .unwrap();
        let mut vit =
            PadVit::load_from_memory_with_runtime(&mut runtime, &read("liveness_vit.onnx"))
                .unwrap();
        let mut flir =
            PadIr::load_from_memory_with_runtime(&mut runtime, &read("flir.onnx")).unwrap();

        let rgb: Vec<u8> = (0..640 * 480 * 3)
            .map(|index| ((index * 37 + 11) % 256) as u8)
            .collect();
        let rgb_view = CanonicalRgbView::try_from_parts(&rgb, 640, 480).unwrap();
        let detector_input = DetectorInput::from_rgb(rgb_view);
        let detections_a = detector.detect(&detector_input).unwrap();
        let detections_b = detector.detect(&detector_input).unwrap();
        assert_eq!(detections_a.len(), detections_b.len());
        assert!(detections_a.iter().zip(&detections_b).all(|(a, b)| {
            a.bbox == b.bbox && a.score == b.score && a.landmarks == b.landmarks
        }));

        let mesh_input = mesh
            .prepare_input(rgb_view, [160.0, 80.0, 480.0, 400.0])
            .unwrap();
        assert_eq!(
            mesh.landmarks(&mesh_input).unwrap(),
            mesh.landmarks(&mesh_input).unwrap()
        );

        let chip: Vec<u8> = (0..112 * 112 * 3)
            .map(|index| ((index * 41 + 7) % 256) as u8)
            .collect();
        let embedding_input = ArcFaceInput::try_from_aligned_rgb(chip).unwrap();
        assert_eq!(
            embedder.embed(&embedding_input).unwrap(),
            embedder.embed(&embedding_input).unwrap()
        );

        let blaze_input = BlazeFaceInput::new(rgb_view);
        assert_eq!(
            blaze.detect_top(&blaze_input).unwrap(),
            blaze.detect_top(&blaze_input).unwrap()
        );

        let vit_input = VitRgbPadInput::new(rgb_view, [160.0, 80.0, 480.0, 400.0]);
        assert_eq!(
            vit.p_spoof(&vit_input).unwrap(),
            vit.p_spoof(&vit_input).unwrap()
        );

        let grey: Vec<u8> = (0..640 * 480)
            .map(|index| ((index * 43 + 13) % 256) as u8)
            .collect();
        let grey_view = CanonicalGreyView::try_from_parts(&grey, 640, 480).unwrap();
        let flir_input = FlirIrPadInput::new(grey_view, [160.0, 80.0, 480.0, 400.0]);
        assert_eq!(
            flir.p_fake(&flir_input).unwrap(),
            flir.p_fake(&flir_input).unwrap()
        );
    }
}
