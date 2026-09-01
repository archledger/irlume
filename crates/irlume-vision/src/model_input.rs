// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright the irlume contributors.

use std::num::NonZeroU32;

use crate::{align, Landmarks5};

/// Closed identifiers for the production model input contracts.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ModelInputContractId {
    YuNetLetterbox640V1,
    ArcFace112RgbV1,
    VitRgbPadM96V1,
    FlirIrPad112V1,
    BlazeFaceLetterbox128V1,
    BlazeFaceFullRangeLetterbox192V1,
    FaceMesh192RgbV1,
    FaceMesh256RgbV1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TensorLayout {
    Nchw,
    Nhwc,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChannelOrder {
    Rgb,
    Bgr,
    ReplicatedGrey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NumericType {
    Float32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueRange {
    ZeroTo255,
    MinusOneToOne,
    ZeroToOne,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Normalization {
    None,
    ArcFace128,
    CenteredUnit255,
    Centered128,
    Centered127_5,
    DivideBy255,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CropPolicy {
    TopLeftSquareLetterbox,
    ArcFaceFivePoint112,
    BboxMargin96Over112Clamped,
    FlirPad16Resize128Center112,
    SquareZeroPadLetterbox,
    SquareBboxMarginOneQuarter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModelInputContract {
    id: ModelInputContractId,
    shape: [usize; 4],
    layout: TensorLayout,
    channel_order: ChannelOrder,
    numeric_type: NumericType,
    value_range: ValueRange,
    normalization: Normalization,
    crop_policy: CropPolicy,
    preprocessing_version: u16,
}

impl ModelInputContract {
    #[must_use]
    pub const fn id(self) -> ModelInputContractId {
        self.id
    }

    #[must_use]
    pub const fn shape(self) -> [usize; 4] {
        self.shape
    }

    #[must_use]
    pub const fn layout(self) -> TensorLayout {
        self.layout
    }

    #[must_use]
    pub const fn channel_order(self) -> ChannelOrder {
        self.channel_order
    }

    #[must_use]
    pub const fn numeric_type(self) -> NumericType {
        self.numeric_type
    }

    #[must_use]
    pub const fn value_range(self) -> ValueRange {
        self.value_range
    }

    #[must_use]
    pub const fn normalization(self) -> Normalization {
        self.normalization
    }

    #[must_use]
    pub const fn crop_policy(self) -> CropPolicy {
        self.crop_policy
    }

    #[must_use]
    pub const fn preprocessing_version(self) -> u16 {
        self.preprocessing_version
    }
}

const PRODUCTION_IDS: [ModelInputContractId; 8] = [
    ModelInputContractId::YuNetLetterbox640V1,
    ModelInputContractId::ArcFace112RgbV1,
    ModelInputContractId::VitRgbPadM96V1,
    ModelInputContractId::FlirIrPad112V1,
    ModelInputContractId::BlazeFaceLetterbox128V1,
    ModelInputContractId::BlazeFaceFullRangeLetterbox192V1,
    ModelInputContractId::FaceMesh192RgbV1,
    ModelInputContractId::FaceMesh256RgbV1,
];

#[derive(Clone, Copy, Debug, Default)]
pub struct ModelContractSet;

impl ModelContractSet {
    #[must_use]
    pub const fn production_v1() -> Self {
        Self
    }

    #[must_use]
    pub const fn ids(self) -> &'static [ModelInputContractId] {
        &PRODUCTION_IDS
    }

    #[must_use]
    pub const fn require(self, id: ModelInputContractId) -> Option<ModelInputContract> {
        Some(contract(id))
    }
}

const fn contract(id: ModelInputContractId) -> ModelInputContract {
    let (shape, layout, channel_order, value_range, normalization, crop_policy) = match id {
        ModelInputContractId::YuNetLetterbox640V1 => (
            [1, 3, 640, 640],
            TensorLayout::Nchw,
            ChannelOrder::Bgr,
            ValueRange::ZeroTo255,
            Normalization::None,
            CropPolicy::TopLeftSquareLetterbox,
        ),
        ModelInputContractId::ArcFace112RgbV1 => (
            [1, 3, 112, 112],
            TensorLayout::Nchw,
            ChannelOrder::Rgb,
            ValueRange::MinusOneToOne,
            Normalization::ArcFace128,
            CropPolicy::ArcFaceFivePoint112,
        ),
        ModelInputContractId::VitRgbPadM96V1 => (
            [1, 3, 224, 224],
            TensorLayout::Nchw,
            ChannelOrder::Rgb,
            ValueRange::MinusOneToOne,
            Normalization::CenteredUnit255,
            CropPolicy::BboxMargin96Over112Clamped,
        ),
        ModelInputContractId::FlirIrPad112V1 => (
            [1, 3, 112, 112],
            TensorLayout::Nchw,
            ChannelOrder::ReplicatedGrey,
            ValueRange::MinusOneToOne,
            Normalization::Centered128,
            CropPolicy::FlirPad16Resize128Center112,
        ),
        ModelInputContractId::BlazeFaceLetterbox128V1 => (
            [1, 128, 128, 3],
            TensorLayout::Nhwc,
            ChannelOrder::Rgb,
            ValueRange::MinusOneToOne,
            Normalization::Centered127_5,
            CropPolicy::SquareZeroPadLetterbox,
        ),
        ModelInputContractId::BlazeFaceFullRangeLetterbox192V1 => (
            [1, 192, 192, 3],
            TensorLayout::Nhwc,
            ChannelOrder::Rgb,
            ValueRange::MinusOneToOne,
            Normalization::Centered127_5,
            CropPolicy::SquareZeroPadLetterbox,
        ),
        ModelInputContractId::FaceMesh192RgbV1 | ModelInputContractId::FaceMesh256RgbV1 => (
            match id {
                ModelInputContractId::FaceMesh192RgbV1 => [1, 192, 192, 3],
                _ => [1, 256, 256, 3],
            },
            TensorLayout::Nhwc,
            ChannelOrder::Rgb,
            ValueRange::ZeroToOne,
            Normalization::DivideBy255,
            CropPolicy::SquareBboxMarginOneQuarter,
        ),
    };
    ModelInputContract {
        id,
        shape,
        layout,
        channel_order,
        numeric_type: NumericType::Float32,
        value_range,
        normalization,
        crop_policy,
        preprocessing_version: 1,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ModelInputError {
    #[error("model input geometry must be nonzero")]
    InvalidGeometry,
    #[error("model input payload length disagrees with geometry")]
    PayloadLength,
    #[error("model input contract does not match the model")]
    ContractMismatch,
    #[error("model input face geometry is invalid: {0}")]
    InvalidFaceGeometry(String),
    #[error("model input preprocessing failed: {0}")]
    Preprocessing(String),
}

impl From<ModelInputError> for irlume_common::Error {
    fn from(error: ModelInputError) -> Self {
        Self::Protocol(error.to_string())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CanonicalRgbView<'a> {
    pixels: &'a [u8],
    width: NonZeroU32,
    height: NonZeroU32,
}

impl<'a> CanonicalRgbView<'a> {
    /// Validate an immutable RGB8 payload against its geometry.
    ///
    /// # Errors
    ///
    /// Returns an error for zero geometry, arithmetic overflow, or a payload
    /// length other than `width * height * 3`.
    pub fn try_from_parts(
        pixels: &'a [u8],
        width: u32,
        height: u32,
    ) -> Result<Self, ModelInputError> {
        let width = NonZeroU32::new(width).ok_or(ModelInputError::InvalidGeometry)?;
        let height = NonZeroU32::new(height).ok_or(ModelInputError::InvalidGeometry)?;
        let expected = usize::try_from(width.get())
            .ok()
            .and_then(|w| {
                usize::try_from(height.get())
                    .ok()
                    .and_then(|h| w.checked_mul(h))
            })
            .and_then(|pixels| pixels.checked_mul(3))
            .ok_or(ModelInputError::PayloadLength)?;
        if pixels.len() != expected {
            return Err(ModelInputError::PayloadLength);
        }
        Ok(Self {
            pixels,
            width,
            height,
        })
    }

    /// Validate an existing RGB view.
    ///
    /// # Errors
    ///
    /// Returns an error when the view has invalid geometry or payload length.
    pub fn try_from_align(view: &align::RgbView<'a>) -> Result<Self, ModelInputError> {
        Self::try_from_parts(view.data, view.width, view.height)
    }

    #[must_use]
    pub const fn pixels(self) -> &'a [u8] {
        self.pixels
    }

    #[must_use]
    pub const fn width(self) -> u32 {
        self.width.get()
    }

    #[must_use]
    pub const fn height(self) -> u32 {
        self.height.get()
    }

    pub(crate) const fn as_align(self) -> align::RgbView<'a> {
        align::RgbView {
            data: self.pixels,
            width: self.width.get(),
            height: self.height.get(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CanonicalGreyView<'a> {
    pixels: &'a [u8],
    width: NonZeroU32,
    height: NonZeroU32,
}

impl<'a> CanonicalGreyView<'a> {
    /// Validate an immutable GREY8 payload against its geometry.
    ///
    /// # Errors
    ///
    /// Returns an error for zero geometry, arithmetic overflow, or a payload
    /// length other than `width * height`.
    pub fn try_from_parts(
        pixels: &'a [u8],
        width: u32,
        height: u32,
    ) -> Result<Self, ModelInputError> {
        let width = NonZeroU32::new(width).ok_or(ModelInputError::InvalidGeometry)?;
        let height = NonZeroU32::new(height).ok_or(ModelInputError::InvalidGeometry)?;
        let expected = usize::try_from(width.get())
            .ok()
            .and_then(|w| {
                usize::try_from(height.get())
                    .ok()
                    .and_then(|h| w.checked_mul(h))
            })
            .ok_or(ModelInputError::PayloadLength)?;
        if pixels.len() != expected {
            return Err(ModelInputError::PayloadLength);
        }
        Ok(Self {
            pixels,
            width,
            height,
        })
    }

    /// Validate an existing GREY8 view.
    ///
    /// # Errors
    ///
    /// Returns an error when the view has invalid geometry or payload length.
    pub fn try_from_align(view: &align::Grey8View<'a>) -> Result<Self, ModelInputError> {
        Self::try_from_parts(view.data, view.width, view.height)
    }

    #[must_use]
    pub const fn pixels(self) -> &'a [u8] {
        self.pixels
    }

    #[must_use]
    pub const fn width(self) -> u32 {
        self.width.get()
    }

    #[must_use]
    pub const fn height(self) -> u32 {
        self.height.get()
    }

    pub(crate) const fn as_align(self) -> align::Grey8View<'a> {
        align::Grey8View {
            data: self.pixels,
            width: self.width.get(),
            height: self.height.get(),
        }
    }
}

#[derive(Clone, Copy)]
enum CanonicalView<'a> {
    Rgb(CanonicalRgbView<'a>),
    Grey(CanonicalGreyView<'a>),
}

impl CanonicalView<'_> {
    const fn width(self) -> u32 {
        match self {
            Self::Rgb(view) => view.width(),
            Self::Grey(view) => view.width(),
        }
    }

    const fn height(self) -> u32 {
        match self {
            Self::Rgb(view) => view.height(),
            Self::Grey(view) => view.height(),
        }
    }

    fn sample_bilinear(self, x: f32, y: f32) -> [f32; 3] {
        match self {
            Self::Rgb(view) => view.as_align().sample_bilinear(x, y),
            Self::Grey(view) => view.as_align().sample_bilinear(x, y),
        }
    }
}

#[derive(Clone, Copy)]
pub struct DetectorInput<'a> {
    view: CanonicalView<'a>,
    contract: ModelInputContractId,
}

impl<'a> DetectorInput<'a> {
    #[must_use]
    pub const fn from_rgb(view: CanonicalRgbView<'a>) -> Self {
        Self {
            view: CanonicalView::Rgb(view),
            contract: ModelInputContractId::YuNetLetterbox640V1,
        }
    }

    #[must_use]
    pub const fn from_grey(view: CanonicalGreyView<'a>) -> Self {
        Self {
            view: CanonicalView::Grey(view),
            contract: ModelInputContractId::YuNetLetterbox640V1,
        }
    }

    pub(crate) fn require(&self, expected: ModelInputContractId) -> Result<(), ModelInputError> {
        require_contract(self.contract, expected)
    }

    pub(crate) const fn width(&self) -> u32 {
        self.view.width()
    }

    pub(crate) const fn height(&self) -> u32 {
        self.view.height()
    }

    pub(crate) fn sample_bilinear(&self, x: f32, y: f32) -> [f32; 3] {
        self.view.sample_bilinear(x, y)
    }
}

pub struct ArcFaceInput {
    chip_rgb: Vec<u8>,
    tensor_nchw: Vec<f32>,
    contract: ModelInputContractId,
}

/// Explicit measurement-only ArcFace tensor used by normalization benches.
pub struct ArcFaceMeasurementInput {
    tensor_nchw: Vec<f32>,
}

impl ArcFaceMeasurementInput {
    /// Wrap an intentionally varied ArcFace tensor for measurement tooling.
    ///
    /// # Errors
    ///
    /// Returns an error unless the tensor has the frozen 112x112x3 length.
    pub fn try_from_tensor(tensor_nchw: Vec<f32>) -> Result<Self, ModelInputError> {
        let expected = align::OUT_SIZE as usize * align::OUT_SIZE as usize * 3;
        if tensor_nchw.len() != expected {
            return Err(ModelInputError::PayloadLength);
        }
        Ok(Self { tensor_nchw })
    }

    #[must_use]
    pub fn tensor(&self) -> &[f32] {
        &self.tensor_nchw
    }
}

impl ArcFaceInput {
    /// Align an RGB face and construct the frozen ArcFace tensor.
    ///
    /// # Errors
    ///
    /// Returns an error when alignment or tensor validation fails.
    pub fn from_rgb(
        view: CanonicalRgbView<'_>,
        landmarks: &Landmarks5,
    ) -> Result<Self, ModelInputError> {
        let chip = align::align_to_arcface(&view.as_align(), landmarks)
            .map_err(|error| ModelInputError::Preprocessing(error.to_string()))?;
        Self::try_from_aligned_rgb(chip)
    }

    /// Align a GREY8 face and construct the replicated-grey ArcFace tensor.
    ///
    /// # Errors
    ///
    /// Returns an error when alignment or tensor validation fails.
    pub fn from_grey(
        view: CanonicalGreyView<'_>,
        landmarks: &Landmarks5,
    ) -> Result<Self, ModelInputError> {
        let rgb = grey_to_rgb(view.pixels());
        let rgb = CanonicalRgbView::try_from_parts(&rgb, view.width(), view.height())?;
        Self::from_rgb(rgb, landmarks)
    }

    /// Construct input from an already aligned 112x112 RGB chip.
    ///
    /// # Errors
    ///
    /// Returns an error unless the chip has the frozen ArcFace payload length.
    pub fn try_from_aligned_rgb(chip_rgb: Vec<u8>) -> Result<Self, ModelInputError> {
        let expected = align::OUT_SIZE as usize * align::OUT_SIZE as usize * 3;
        if chip_rgb.len() != expected {
            return Err(ModelInputError::PayloadLength);
        }
        let tensor_nchw = align::preprocess_arcface(&chip_rgb);
        Ok(Self {
            chip_rgb,
            tensor_nchw,
            contract: ModelInputContractId::ArcFace112RgbV1,
        })
    }

    /// Copy and validate an already aligned 112x112 RGB chip.
    ///
    /// # Errors
    ///
    /// Returns an error unless the chip has the frozen ArcFace payload length.
    pub fn try_from_aligned_rgb_slice(chip_rgb: &[u8]) -> Result<Self, ModelInputError> {
        Self::try_from_aligned_rgb(chip_rgb.to_vec())
    }

    pub fn flipped(&self) -> Self {
        let chip_rgb = align::flip_h(&self.chip_rgb);
        let tensor_nchw = align::preprocess_arcface(&chip_rgb);
        Self {
            chip_rgb,
            tensor_nchw,
            contract: ModelInputContractId::ArcFace112RgbV1,
        }
    }

    #[must_use]
    pub fn chip_rgb(&self) -> &[u8] {
        &self.chip_rgb
    }

    #[must_use]
    pub fn tensor(&self) -> &[f32] {
        &self.tensor_nchw
    }

    pub(crate) fn require(&self, expected: ModelInputContractId) -> Result<(), ModelInputError> {
        require_contract(self.contract, expected)
    }
}

pub struct VitRgbPadInput {
    tensor_nchw: Vec<f32>,
    contract: ModelInputContractId,
}

impl VitRgbPadInput {
    #[must_use]
    pub fn new(view: CanonicalRgbView<'_>, bbox: [f32; 4]) -> Self {
        Self {
            tensor_nchw: pad_vit_tensor(view, &bbox),
            contract: ModelInputContractId::VitRgbPadM96V1,
        }
    }

    #[must_use]
    pub fn tensor(&self) -> &[f32] {
        &self.tensor_nchw
    }

    pub(crate) fn require(&self, expected: ModelInputContractId) -> Result<(), ModelInputError> {
        require_contract(self.contract, expected)
    }
}

pub struct FlirIrPadInput {
    tensor_nchw: Vec<f32>,
    contract: ModelInputContractId,
}

impl FlirIrPadInput {
    #[must_use]
    pub fn new(view: CanonicalGreyView<'_>, bbox: [f32; 4]) -> Self {
        Self {
            tensor_nchw: flir_ir_tensor(view, &bbox),
            contract: ModelInputContractId::FlirIrPad112V1,
        }
    }

    #[must_use]
    pub fn tensor(&self) -> &[f32] {
        &self.tensor_nchw
    }

    pub(crate) fn require(&self, expected: ModelInputContractId) -> Result<(), ModelInputError> {
        require_contract(self.contract, expected)
    }
}

pub struct BlazeFaceInput {
    tensor_nhwc: Vec<f32>,
    frame_side: f32,
    contract: ModelInputContractId,
}

pub struct FullRangeBlazeFaceInput {
    tensor_nhwc: Vec<f32>,
    frame_side: f32,
    contract: ModelInputContractId,
}

impl FullRangeBlazeFaceInput {
    #[must_use]
    pub fn new(view: CanonicalRgbView<'_>) -> Self {
        Self {
            tensor_nhwc: square_letterbox_tensor(view, 192),
            frame_side: view.width().max(view.height()) as f32,
            contract: ModelInputContractId::BlazeFaceFullRangeLetterbox192V1,
        }
    }

    #[must_use]
    pub fn tensor(&self) -> &[f32] {
        &self.tensor_nhwc
    }

    pub(crate) const fn frame_side(&self) -> f32 {
        self.frame_side
    }

    /// Verify this tensor belongs to `expected` before inference.
    ///
    /// # Errors
    ///
    /// Returns [`ModelInputError::ContractMismatch`] for another contract.
    pub fn require(&self, expected: ModelInputContractId) -> Result<(), ModelInputError> {
        require_contract(self.contract, expected)
    }
}

impl BlazeFaceInput {
    #[must_use]
    pub fn new(view: CanonicalRgbView<'_>) -> Self {
        Self {
            tensor_nhwc: square_letterbox_tensor(view, 128),
            frame_side: view.width().max(view.height()) as f32,
            contract: ModelInputContractId::BlazeFaceLetterbox128V1,
        }
    }

    #[must_use]
    pub fn tensor(&self) -> &[f32] {
        &self.tensor_nhwc
    }

    pub(crate) const fn frame_side(&self) -> f32 {
        self.frame_side
    }

    /// Verify this tensor belongs to `expected` before inference.
    ///
    /// # Errors
    ///
    /// Returns [`ModelInputError::ContractMismatch`] for another contract.
    pub fn require(&self, expected: ModelInputContractId) -> Result<(), ModelInputError> {
        require_contract(self.contract, expected)
    }
}

#[derive(Debug)]
pub struct FaceMeshInput {
    tensor_nhwc: Vec<f32>,
    input_side: usize,
    crop_x: f32,
    crop_y: f32,
    crop_side: f32,
    contract: ModelInputContractId,
}

/// FaceMesh input for direct measurement runtimes.
///
/// This preserves the selected production contract and preprocessing while
/// allowing parity tooling to inject an explicit bounded horizontal crop skew.
pub struct FaceMeshMeasurementInput {
    input: FaceMeshInput,
    horizontal_skew: f32,
}

impl FaceMeshMeasurementInput {
    /// Construct an unskewed measurement input through the production adapter.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported contract or invalid face geometry.
    pub fn new(
        view: CanonicalRgbView<'_>,
        bbox: [f32; 4],
        contract: ModelInputContractId,
    ) -> Result<Self, ModelInputError> {
        Self::with_horizontal_skew(view, bbox, contract, 0.0)
    }

    /// Construct a measurement input with an explicit horizontal crop skew.
    ///
    /// # Errors
    ///
    /// Returns an error unless the skew is finite and no larger than one
    /// quarter of the selected FaceMesh crop.
    pub fn with_horizontal_skew(
        view: CanonicalRgbView<'_>,
        bbox: [f32; 4],
        contract: ModelInputContractId,
        horizontal_skew: f32,
    ) -> Result<Self, ModelInputError> {
        Ok(Self {
            input: FaceMeshInput::new_for_contract_with_skew(
                view,
                bbox,
                contract,
                horizontal_skew,
            )?,
            horizontal_skew,
        })
    }

    #[must_use]
    pub fn tensor(&self) -> &[f32] {
        self.input.tensor()
    }

    #[must_use]
    pub const fn input_side(&self) -> usize {
        self.input.input_side
    }

    #[must_use]
    pub const fn crop(&self) -> (f32, f32, f32) {
        (self.input.crop_x, self.input.crop_y, self.input.crop_side)
    }

    #[must_use]
    pub const fn contract(&self) -> ModelInputContractId {
        self.input.contract
    }

    #[must_use]
    pub const fn horizontal_skew(&self) -> f32 {
        self.horizontal_skew
    }
}

impl FaceMeshInput {
    /// Construct the current 256-side FaceMesh input contract.
    ///
    /// # Errors
    ///
    /// Returns an error when the face box is invalid.
    pub fn new(view: CanonicalRgbView<'_>, bbox: [f32; 4]) -> Result<Self, ModelInputError> {
        Self::new_for_contract(view, bbox, ModelInputContractId::FaceMesh256RgbV1)
    }

    /// Construct one of the closed 192-side or 256-side FaceMesh contracts.
    ///
    /// # Errors
    ///
    /// Returns an error for another contract or invalid face geometry.
    pub fn new_for_contract(
        view: CanonicalRgbView<'_>,
        bbox: [f32; 4],
        contract: ModelInputContractId,
    ) -> Result<Self, ModelInputError> {
        Self::new_for_contract_with_skew(view, bbox, contract, 0.0)
    }

    fn new_for_contract_with_skew(
        view: CanonicalRgbView<'_>,
        bbox: [f32; 4],
        contract: ModelInputContractId,
        horizontal_skew: f32,
    ) -> Result<Self, ModelInputError> {
        let input_side = match contract {
            ModelInputContractId::FaceMesh192RgbV1 => 192,
            ModelInputContractId::FaceMesh256RgbV1 => 256,
            _ => return Err(ModelInputError::ContractMismatch),
        };
        crate::mesh_box_valid(&bbox, view.width(), view.height())
            .map_err(ModelInputError::InvalidFaceGeometry)?;
        const MARGIN: f32 = 0.25;
        let (cx, cy) = ((bbox[0] + bbox[2]) * 0.5, (bbox[1] + bbox[3]) * 0.5);
        let half = 0.5 * (bbox[2] - bbox[0]).max(bbox[3] - bbox[1]) * (1.0 + 2.0 * MARGIN);
        let crop_side = 2.0 * half;
        if !horizontal_skew.is_finite() || horizontal_skew.abs() > crop_side * 0.25 {
            return Err(ModelInputError::Preprocessing(
                "FaceMesh measurement skew must be finite and within one quarter crop".into(),
            ));
        }
        let (crop_x, crop_y) = (cx - half + horizontal_skew, cy - half);
        let mut tensor_nhwc = vec![0.0f32; input_side * input_side * 3];
        let sampler = view.as_align();
        for oy in 0..input_side {
            for ox in 0..input_side {
                let sx = crop_x + (ox as f32 + 0.5) / input_side as f32 * crop_side;
                let sy = crop_y + (oy as f32 + 0.5) / input_side as f32 * crop_side;
                let pixel = sampler.sample_bilinear(sx, sy);
                let index = (oy * input_side + ox) * 3;
                tensor_nhwc[index] = pixel[0] / 255.0;
                tensor_nhwc[index + 1] = pixel[1] / 255.0;
                tensor_nhwc[index + 2] = pixel[2] / 255.0;
            }
        }
        Ok(Self {
            tensor_nhwc,
            input_side,
            crop_x,
            crop_y,
            crop_side,
            contract,
        })
    }

    #[must_use]
    pub fn tensor(&self) -> &[f32] {
        &self.tensor_nhwc
    }

    pub(crate) const fn input_side(&self) -> usize {
        self.input_side
    }

    pub(crate) const fn crop(&self) -> (f32, f32, f32) {
        (self.crop_x, self.crop_y, self.crop_side)
    }

    pub(crate) fn require(&self, expected: ModelInputContractId) -> Result<(), ModelInputError> {
        require_contract(self.contract, expected)
    }
}

fn require_contract(
    actual: ModelInputContractId,
    expected: ModelInputContractId,
) -> Result<(), ModelInputError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ModelInputError::ContractMismatch)
    }
}

fn grey_to_rgb(grey: &[u8]) -> Vec<u8> {
    let mut rgb = Vec::with_capacity(grey.len() * 3);
    for &value in grey {
        rgb.extend_from_slice(&[value; 3]);
    }
    rgb
}

fn square_letterbox_tensor(view: CanonicalRgbView<'_>, size: usize) -> Vec<f32> {
    let side = view.width().max(view.height()) as f32;
    let sampler = view.as_align();
    let mut tensor = vec![0.0f32; size * size * 3];
    for oy in 0..size {
        for ox in 0..size {
            let sx = (ox as f32 + 0.5) / size as f32 * side;
            let sy = (oy as f32 + 0.5) / size as f32 * side;
            if sx >= view.width() as f32 || sy >= view.height() as f32 {
                continue;
            }
            let pixel = sampler.sample_bilinear(sx, sy);
            let index = (oy * size + ox) * 3;
            tensor[index] = (pixel[0] - 127.5) / 127.5;
            tensor[index + 1] = (pixel[1] - 127.5) / 127.5;
            tensor[index + 2] = (pixel[2] - 127.5) / 127.5;
        }
    }
    tensor
}

fn pad_vit_tensor(view: CanonicalRgbView<'_>, bbox: &[f32; 4]) -> Vec<f32> {
    const SIZE: usize = 224;
    const MARGIN: f32 = 96.0 / 112.0;
    let (fw, fh) = (view.width() as f32, view.height() as f32);
    let (bw, bh) = (bbox[2] - bbox[0], bbox[3] - bbox[1]);
    let x1 = (bbox[0] - bw * MARGIN).max(0.0);
    let y1 = (bbox[1] - bh * MARGIN).max(0.0);
    let x2 = (bbox[2] + bw * MARGIN).min(fw - 1.0);
    let y2 = (bbox[3] + bh * MARGIN).min(fh - 1.0);
    let (cw, ch) = ((x2 - x1).max(1.0), (y2 - y1).max(1.0));
    let mut tensor = vec![0.0f32; 3 * SIZE * SIZE];
    let plane = SIZE * SIZE;
    let sampler = view.as_align();
    for oy in 0..SIZE {
        for ox in 0..SIZE {
            let fx = x1 + (ox as f32 + 0.5) * cw / SIZE as f32 - 0.5;
            let fy = y1 + (oy as f32 + 0.5) * ch / SIZE as f32 - 0.5;
            let pixel = sampler.sample_bilinear(fx.clamp(0.0, fw - 1.0), fy.clamp(0.0, fh - 1.0));
            let index = oy * SIZE + ox;
            tensor[index] = (pixel[0] / 255.0 - 0.5) / 0.5;
            tensor[plane + index] = (pixel[1] / 255.0 - 0.5) / 0.5;
            tensor[2 * plane + index] = (pixel[2] / 255.0 - 0.5) / 0.5;
        }
    }
    tensor
}

fn flir_ir_tensor(view: CanonicalGreyView<'_>, bbox: &[f32; 4]) -> Vec<f32> {
    const PAD: i64 = 16;
    const SIZE: usize = 112;
    let (fw, fh) = (i64::from(view.width()), i64::from(view.height()));
    let mut bounds = [
        bbox[0] as i64,
        bbox[1] as i64,
        bbox[2] as i64,
        bbox[3] as i64,
    ];
    let px = (bounds[2] - bounds[0] + 1) * PAD / 112;
    let py = (bounds[3] - bounds[1] + 1) * PAD / 112;
    bounds = [
        (bounds[0] - px).max(0),
        (bounds[1] - py).max(0),
        (bounds[2] + px).min(fw - 1),
        (bounds[3] + py).min(fh - 1),
    ];
    let (ph, pw) = (bounds[3] - bounds[1] + 1, bounds[2] - bounds[0] + 1);
    let dst_size = if pw > ph {
        let offset = (pw - ph) / 2;
        bounds[1] = (bounds[1] - offset).max(0);
        bounds[3] = (bounds[1] + pw - 1).min(fh - 1);
        pw
    } else {
        let offset = (ph - pw) / 2;
        bounds[0] = (bounds[0] - offset).max(0);
        bounds[2] = (bounds[0] + ph - 1).min(fw - 1);
        ph
    } as f32;
    let xo = (dst_size as i64 - (bounds[2] - bounds[0] + 1)) / 2;
    let yo = (dst_size as i64 - (bounds[3] - bounds[1] + 1)) / 2;
    let scale = dst_size / 128.0;
    let mut tensor = vec![0.0f32; 3 * SIZE * SIZE];
    let plane = SIZE * SIZE;
    let sampler = view.as_align();
    for oy in 0..SIZE {
        for ox in 0..SIZE {
            let sqx = ((ox + 8) as f32 + 0.5) * scale - 0.5;
            let sqy = ((oy + 8) as f32 + 0.5) * scale - 0.5;
            let fx = sqx - xo as f32 + bounds[0] as f32;
            let fy = sqy - yo as f32 + bounds[1] as f32;
            let value = if fx < bounds[0] as f32 - 0.5
                || fy < bounds[1] as f32 - 0.5
                || fx > bounds[2] as f32 + 0.5
                || fy > bounds[3] as f32 + 0.5
            {
                127.0
            } else {
                sampler.sample_bilinear_grey(fx, fy)
            };
            let normalized = (value - 127.5) * 0.007_812_5;
            let index = oy * SIZE + ox;
            tensor[index] = normalized;
            tensor[plane + index] = normalized;
            tensor[2 * plane + index] = normalized;
        }
    }
    tensor
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_contract_set_is_closed_and_frozen() {
        let contracts = ModelContractSet::production_v1();
        assert_eq!(
            contracts.ids(),
            &[
                ModelInputContractId::YuNetLetterbox640V1,
                ModelInputContractId::ArcFace112RgbV1,
                ModelInputContractId::VitRgbPadM96V1,
                ModelInputContractId::FlirIrPad112V1,
                ModelInputContractId::BlazeFaceLetterbox128V1,
                ModelInputContractId::BlazeFaceFullRangeLetterbox192V1,
                ModelInputContractId::FaceMesh192RgbV1,
                ModelInputContractId::FaceMesh256RgbV1,
            ]
        );

        let expected = [
            (
                ModelInputContractId::YuNetLetterbox640V1,
                [1, 3, 640, 640],
                TensorLayout::Nchw,
                ChannelOrder::Bgr,
                NumericType::Float32,
                ValueRange::ZeroTo255,
                Normalization::None,
                CropPolicy::TopLeftSquareLetterbox,
            ),
            (
                ModelInputContractId::ArcFace112RgbV1,
                [1, 3, 112, 112],
                TensorLayout::Nchw,
                ChannelOrder::Rgb,
                NumericType::Float32,
                ValueRange::MinusOneToOne,
                Normalization::ArcFace128,
                CropPolicy::ArcFaceFivePoint112,
            ),
            (
                ModelInputContractId::VitRgbPadM96V1,
                [1, 3, 224, 224],
                TensorLayout::Nchw,
                ChannelOrder::Rgb,
                NumericType::Float32,
                ValueRange::MinusOneToOne,
                Normalization::CenteredUnit255,
                CropPolicy::BboxMargin96Over112Clamped,
            ),
            (
                ModelInputContractId::FlirIrPad112V1,
                [1, 3, 112, 112],
                TensorLayout::Nchw,
                ChannelOrder::ReplicatedGrey,
                NumericType::Float32,
                ValueRange::MinusOneToOne,
                Normalization::Centered128,
                CropPolicy::FlirPad16Resize128Center112,
            ),
            (
                ModelInputContractId::BlazeFaceLetterbox128V1,
                [1, 128, 128, 3],
                TensorLayout::Nhwc,
                ChannelOrder::Rgb,
                NumericType::Float32,
                ValueRange::MinusOneToOne,
                Normalization::Centered127_5,
                CropPolicy::SquareZeroPadLetterbox,
            ),
            (
                ModelInputContractId::FaceMesh192RgbV1,
                [1, 192, 192, 3],
                TensorLayout::Nhwc,
                ChannelOrder::Rgb,
                NumericType::Float32,
                ValueRange::ZeroToOne,
                Normalization::DivideBy255,
                CropPolicy::SquareBboxMarginOneQuarter,
            ),
            (
                ModelInputContractId::FaceMesh256RgbV1,
                [1, 256, 256, 3],
                TensorLayout::Nhwc,
                ChannelOrder::Rgb,
                NumericType::Float32,
                ValueRange::ZeroToOne,
                Normalization::DivideBy255,
                CropPolicy::SquareBboxMarginOneQuarter,
            ),
            (
                ModelInputContractId::BlazeFaceFullRangeLetterbox192V1,
                [1, 192, 192, 3],
                TensorLayout::Nhwc,
                ChannelOrder::Rgb,
                NumericType::Float32,
                ValueRange::MinusOneToOne,
                Normalization::Centered127_5,
                CropPolicy::SquareZeroPadLetterbox,
            ),
        ];

        for (id, shape, layout, channels, numeric, range, normalization, crop) in expected {
            let contract = contracts.require(id).expect("production contract");
            assert_eq!(contract.shape(), shape);
            assert_eq!(contract.layout(), layout);
            assert_eq!(contract.channel_order(), channels);
            assert_eq!(contract.numeric_type(), numeric);
            assert_eq!(contract.value_range(), range);
            assert_eq!(contract.normalization(), normalization);
            assert_eq!(contract.crop_policy(), crop);
            assert_eq!(contract.preprocessing_version(), 1);
        }
    }

    #[test]
    fn canonical_views_reject_zero_geometry_overflow_and_wrong_payload_lengths() {
        assert_eq!(
            CanonicalRgbView::try_from_parts(&[], 0, 1).unwrap_err(),
            ModelInputError::InvalidGeometry
        );
        assert_eq!(
            CanonicalGreyView::try_from_parts(&[], 1, 0).unwrap_err(),
            ModelInputError::InvalidGeometry
        );
        assert_eq!(
            CanonicalRgbView::try_from_parts(&[0; 11], 2, 2).unwrap_err(),
            ModelInputError::PayloadLength
        );
        assert_eq!(
            CanonicalGreyView::try_from_parts(&[0; 3], 2, 2).unwrap_err(),
            ModelInputError::PayloadLength
        );
        assert_eq!(
            CanonicalRgbView::try_from_parts(&[], u32::MAX, u32::MAX).unwrap_err(),
            ModelInputError::PayloadLength
        );
    }

    #[test]
    fn matching_typed_inputs_reject_other_model_contracts() {
        let rgb = CanonicalRgbView::try_from_parts(&[255, 0, 0], 1, 1).unwrap();
        let input = BlazeFaceInput::new(rgb);
        assert_eq!(
            input
                .require(ModelInputContractId::FaceMesh256RgbV1)
                .unwrap_err(),
            ModelInputError::ContractMismatch
        );
    }

    #[test]
    fn blazeface_tensor_preserves_rgb_nhwc_and_centered_range() {
        let rgb = CanonicalRgbView::try_from_parts(&[255, 0, 127], 1, 1).unwrap();
        let input = BlazeFaceInput::new(rgb);
        assert_eq!(input.tensor().len(), 128 * 128 * 3);
        assert!((input.tensor()[0] - 1.0).abs() < 1e-6);
        assert!((input.tensor()[1] + 1.0).abs() < 1e-6);
        assert!((input.tensor()[2] - ((127.0 - 127.5) / 127.5)).abs() < 1e-6);
    }

    #[test]
    fn facemesh_tensor_preserves_rgb_nhwc_and_zero_to_one_range() {
        let rgb = CanonicalRgbView::try_from_parts(&[64, 128, 255], 1, 1).unwrap();
        let input = FaceMeshInput::new(rgb, [0.0, 0.0, 1.0, 1.0]).unwrap();
        assert_eq!(input.tensor().len(), 256 * 256 * 3);
        assert!((input.tensor()[0] - 64.0 / 255.0).abs() < 1e-6);
        assert!((input.tensor()[1] - 128.0 / 255.0).abs() < 1e-6);
        assert!((input.tensor()[2] - 1.0).abs() < 1e-6);
    }

    #[test]
    fn full_range_blazeface_contract_and_tensor_are_frozen() {
        let contract = ModelContractSet::production_v1()
            .require(ModelInputContractId::BlazeFaceFullRangeLetterbox192V1)
            .expect("full-range BlazeFace contract");
        assert_eq!(contract.shape(), [1, 192, 192, 3]);
        assert_eq!(contract.layout(), TensorLayout::Nhwc);
        assert_eq!(contract.channel_order(), ChannelOrder::Rgb);
        assert_eq!(contract.normalization(), Normalization::Centered127_5);
        assert_eq!(contract.crop_policy(), CropPolicy::SquareZeroPadLetterbox);

        let rgb = CanonicalRgbView::try_from_parts(&[255, 0, 127], 1, 1).unwrap();
        let input = FullRangeBlazeFaceInput::new(rgb);
        assert_eq!(input.tensor().len(), 192 * 192 * 3);
        assert!((input.tensor()[0] - 1.0).abs() < 1e-6);
        assert!((input.tensor()[1] + 1.0).abs() < 1e-6);
        assert!((input.tensor()[2] - ((127.0 - 127.5) / 127.5)).abs() < 1e-6);
    }

    #[test]
    fn legacy_facemesh_contract_remains_supported() {
        let contract = ModelContractSet::production_v1()
            .require(ModelInputContractId::FaceMesh192RgbV1)
            .expect("legacy FaceMesh contract");
        assert_eq!(contract.shape(), [1, 192, 192, 3]);
        assert_eq!(contract.normalization(), Normalization::DivideBy255);

        let rgb = CanonicalRgbView::try_from_parts(&[64, 128, 255], 1, 1).unwrap();
        let input = FaceMeshInput::new_for_contract(
            rgb,
            [0.0, 0.0, 1.0, 1.0],
            ModelInputContractId::FaceMesh192RgbV1,
        )
        .unwrap();
        assert_eq!(input.tensor().len(), 192 * 192 * 3);
    }

    #[test]
    fn facemesh_measurement_standard_uses_the_production_contract_and_preprocessing() {
        let pixels: Vec<u8> = (0..12 * 10 * 3).map(|i| (i % 251) as u8).collect();
        let rgb = CanonicalRgbView::try_from_parts(&pixels, 12, 10).unwrap();
        let bbox = [2.0, 1.0, 9.0, 8.0];
        let production =
            FaceMeshInput::new_for_contract(rgb, bbox, ModelInputContractId::FaceMesh192RgbV1)
                .unwrap();
        let measurement =
            FaceMeshMeasurementInput::new(rgb, bbox, ModelInputContractId::FaceMesh192RgbV1)
                .unwrap();

        assert_eq!(
            measurement.contract(),
            ModelInputContractId::FaceMesh192RgbV1
        );
        assert_eq!(measurement.horizontal_skew(), 0.0);
        assert_eq!(measurement.tensor(), production.tensor());
    }

    #[test]
    fn facemesh_measurement_skew_is_explicit_finite_and_crop_bounded() {
        let pixels: Vec<u8> = (0..100 * 100 * 3).map(|i| (i % 251) as u8).collect();
        let rgb = CanonicalRgbView::try_from_parts(&pixels, 100, 100).unwrap();
        let bbox = [20.0, 20.0, 60.0, 60.0];
        let standard =
            FaceMeshMeasurementInput::new(rgb, bbox, ModelInputContractId::FaceMesh256RgbV1)
                .unwrap();
        let skewed = FaceMeshMeasurementInput::with_horizontal_skew(
            rgb,
            bbox,
            ModelInputContractId::FaceMesh256RgbV1,
            1.5,
        )
        .unwrap();

        assert_eq!(skewed.contract(), standard.contract());
        assert_eq!(skewed.horizontal_skew(), 1.5);
        assert_eq!(skewed.crop().0 - standard.crop().0, 1.5);
        assert_eq!(skewed.crop().1, standard.crop().1);
        assert_eq!(skewed.crop().2, standard.crop().2);
        assert_ne!(skewed.tensor(), standard.tensor());

        for invalid in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, 15.01] {
            assert!(FaceMeshMeasurementInput::with_horizontal_skew(
                rgb,
                bbox,
                ModelInputContractId::FaceMesh256RgbV1,
                invalid,
            )
            .is_err());
        }
        assert!(FaceMeshMeasurementInput::with_horizontal_skew(
            rgb,
            bbox,
            ModelInputContractId::FaceMesh256RgbV1,
            15.0,
        )
        .is_ok());
    }
}
