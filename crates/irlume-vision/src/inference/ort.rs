// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

//! Provider-free ONNX Runtime CPU adapter.

use super::{
    InferenceSession, ModelCompiler, OwnedTensor, SessionContract, SessionMetadata,
    TensorElementType, TensorMetadata,
};
use irlume_common::Result;
use ort::session::{builder::GraphOptimizationLevel, Session};
use ort::value::{TensorElementType as OrtTensorElementType, TensorRef, ValueType};

struct OrtCpuConfiguration {
    intra_threads: usize,
    optimization_level: u8,
    execution_providers: &'static [&'static str],
}

const fn ort_cpu_configuration() -> OrtCpuConfiguration {
    OrtCpuConfiguration {
        intra_threads: 2,
        optimization_level: 3,
        execution_providers: &[],
    }
}

pub(super) struct OrtCompiler;

impl OrtCompiler {
    pub(super) fn new() -> Result<Self> {
        crate::onnx::ensure_ort_resolvable()?;
        Ok(Self)
    }
}

impl ModelCompiler for OrtCompiler {
    fn compile(
        &mut self,
        model: &[u8],
        contract: &'static SessionContract,
    ) -> Result<InferenceSession> {
        let configuration = ort_cpu_configuration();
        debug_assert!(configuration.execution_providers.is_empty());
        let mut session = Session::builder()
            .map_err(crate::onnx::err)?
            .with_intra_threads(configuration.intra_threads)
            .map_err(crate::onnx::err)?
            .with_optimization_level(match configuration.optimization_level {
                3 => GraphOptimizationLevel::Level3,
                _ => unreachable!("the provider-free CPU configuration is fixed"),
            })
            .map_err(crate::onnx::err)?
            .commit_from_memory(model)
            .map_err(crate::onnx::err)?;

        let metadata = SessionMetadata {
            input: outlet_metadata(
                session
                    .inputs()
                    .first()
                    .ok_or_else(crate::inference::contract_error)?,
            )?,
            outputs: session
                .outputs()
                .iter()
                .map(outlet_metadata)
                .collect::<Result<Vec<_>>>()?,
        };

        InferenceSession::new(contract, metadata, move |input| {
            let shape = input
                .shape
                .iter()
                .copied()
                .map(i64::try_from)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(crate::onnx::err)?;
            let tensor = TensorRef::<f32>::from_array_view((shape, input.values))
                .map_err(crate::onnx::err)?;
            let outputs = session
                .run(ort::inputs![input.name => tensor])
                .map_err(crate::onnx::err)?;
            outputs
                .into_iter()
                .map(|(name, value)| {
                    let (shape, values) = value
                        .try_extract_tensor::<f32>()
                        .map_err(crate::onnx::err)?;
                    let shape = shape
                        .iter()
                        .copied()
                        .map(usize::try_from)
                        .collect::<std::result::Result<Vec<_>, _>>()
                        .map_err(crate::onnx::err)?;
                    Ok(OwnedTensor {
                        name: name.to_owned(),
                        shape,
                        values: values.to_vec(),
                    })
                })
                .collect()
        })
    }
}

fn outlet_metadata(outlet: &ort::value::Outlet) -> Result<TensorMetadata> {
    let ValueType::Tensor { ty, shape, .. } = outlet.dtype() else {
        return Err(crate::inference::contract_error());
    };
    let dimensions = shape
        .iter()
        .copied()
        .map(|dimension| match dimension {
            -1 => Ok(None),
            dimension if dimension >= 0 => usize::try_from(dimension)
                .map(Some)
                .map_err(crate::onnx::err),
            _ => Err(crate::inference::contract_error()),
        })
        .collect::<Result<Vec<_>>>()?;
    let element_type = match ty {
        OrtTensorElementType::Float32 => TensorElementType::F32,
        OrtTensorElementType::Int64 => TensorElementType::I64,
        OrtTensorElementType::Uint8 => TensorElementType::U8,
        _ => TensorElementType::Other,
    };
    Ok(TensorMetadata {
        name: outlet.name().to_owned(),
        dimensions,
        element_type,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inference::{
        DimensionContract::{BatchOneOrDynamic, Fixed},
        SessionContract, TensorContract, TensorInput,
    };

    static OUTPUTS: [TensorContract; 1] = [TensorContract::f32(
        "1333",
        &[BatchOneOrDynamic, Fixed(512)],
    )];
    static AURAFACE: SessionContract = SessionContract {
        model: "auraface",
        input: TensorContract::f32(
            "data",
            &[BatchOneOrDynamic, Fixed(3), Fixed(112), Fixed(112)],
        ),
        outputs: &OUTPUTS,
    };

    #[test]
    fn cpu_configuration_has_no_execution_provider() {
        let configuration = ort_cpu_configuration();
        assert_eq!(configuration.intra_threads, 2);
        assert_eq!(configuration.optimization_level, 3);
        assert!(configuration.execution_providers.is_empty());
    }

    #[test]
    fn cpu_runtime_compiles_named_ports_and_returns_owned_outputs() {
        let model = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../models/glintr100.onnx"
        ))
        .unwrap();
        let mut runtime = crate::inference::CandidateRuntime::ort_cpu().unwrap();
        let mut session = runtime.compile(&model, &AURAFACE).unwrap();
        let values = vec![0.0; 3 * 112 * 112];
        let outputs = session
            .run_f32(TensorInput {
                name: "data",
                shape: &[1, 3, 112, 112],
                values: &values,
            })
            .unwrap();

        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].name, "1333");
        assert_eq!(outputs[0].shape, [1, 512]);
        assert_eq!(outputs[0].values.len(), 512);
    }
}
