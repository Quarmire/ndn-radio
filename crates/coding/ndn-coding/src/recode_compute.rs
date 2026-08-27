//! Register the deterministic `_nc/<vector>` recode as an `ndn-compute`
//! function (feature `f2-recode-compute`).
//!
//! The `_nc/<vector>` mode (doctrine §8) is literally "compute the linear
//! function `<vector>` over this generation" — a *deterministic, transparent*
//! computation. Registering it as a Tier-0 [`ComputeHandler`] surfaces it in
//! `/localhost/nfd/compute/list` and lets it compose with the compute
//! machinery, exactly as the doctrine reserved. The `RecoderFace` still serves
//! the same name natively; this is the alternative compute-framed realization,
//! not a replacement.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use ndn_compute::{ComputeError, ComputeHandler, ComputeService};
use ndn_packet::encode::DataBuilder;
use ndn_packet::{Data, Interest, Name};

use crate::recode::{CodedMetadata, GenerationBuffer, RecodePolicy, naming};

/// A [`ComputeHandler`] answering `…/_gen/<id>/_nc/<vector>` with the exact
/// deterministic combination for `<vector>`, computed from a shared
/// [`GenerationBuffer`]. Deterministic ⇒ `Determinism::Transparent`,
/// freshness-cacheable like any computed Data.
pub struct NcComputeHandler {
    object: Name,
    generation_id: u64,
    buffer: Arc<Mutex<GenerationBuffer>>,
    /// The shared recode kill switch (doctrine §5). When present and `false`, this
    /// handler refuses exactly as the native `RecoderFace` does — without it the
    /// compute-framed path is a bypass of the operator's runtime control. Obtain it
    /// from [`RecoderState::kill_switch`](crate::recode_face::RecoderState::kill_switch)
    /// so both realizations of the same name honour one switch.
    kill_switch: Option<Arc<AtomicBool>>,
}

impl NcComputeHandler {
    /// Construct with no runtime kill switch (only the per-generation `RecodePolicy`
    /// gate applies). Prefer [`with_kill_switch`](Self::with_kill_switch) when a
    /// `RecoderState` serves the same name, so the operator's §5 control covers both.
    pub fn new(object: Name, generation_id: u64, buffer: Arc<Mutex<GenerationBuffer>>) -> Self {
        Self {
            object,
            generation_id,
            buffer,
            kill_switch: None,
        }
    }

    /// Construct sharing a recoder's runtime kill switch (see [`new`](Self::new)).
    pub fn with_kill_switch(
        object: Name,
        generation_id: u64,
        buffer: Arc<Mutex<GenerationBuffer>>,
        kill_switch: Arc<AtomicBool>,
    ) -> Self {
        Self {
            object,
            generation_id,
            buffer,
            kill_switch: Some(kill_switch),
        }
    }
}

impl ComputeHandler for NcComputeHandler {
    async fn handle(&self, interest: &Interest) -> Result<Data, ComputeError> {
        let (object, generation_id, vector) = naming::parse_vector_request(&interest.name)
            .ok_or_else(|| ComputeError::BadRequest("not a _nc/<vector> name".into()))?;
        if object != self.object || generation_id != self.generation_id {
            return Err(ComputeError::NotFound);
        }
        // The SAME two gates the native `RecoderFace::mint_exact` enforces — without them this
        // compute-framed path bypasses both the operator's runtime kill switch (§5) and the
        // generation's `RecodePolicy::None` (recoding forbidden). Answer as "not found" so a
        // disabled/forbidden generation is indistinguishable from an absent one.
        if let Some(sw) = &self.kill_switch
            && !sw.load(Ordering::Relaxed)
        {
            return Err(ComputeError::NotFound);
        }
        let (combo, k, field) = {
            let buf = self.buffer.lock().unwrap();
            if matches!(buf.descriptor().recode, RecodePolicy::None) {
                return Err(ComputeError::NotFound);
            }
            (
                buf.recode_exact(&vector),
                buf.descriptor().k,
                buf.descriptor().field,
            )
        };
        let combo =
            combo.ok_or_else(|| ComputeError::HandlerFailed("generation not full rank".into()))?;
        let meta = CodedMetadata {
            generation_id,
            k,
            field,
            vector: combo.vector,
        };
        let content = meta.prepend(&combo.payload);
        let name = (*interest.name).clone();
        let wire = DataBuilder::new(name, &content).sign_digest_sha256();
        Data::decode(wire).map_err(|e| ComputeError::HandlerFailed(format!("encode: {e}")))
    }
}

/// Register the `_nc` subtree of a generation as a compute function on
/// `service`. After this, `<object>/_gen/<id>/_nc/<vector>` Interests route to
/// the compute face and are answered by [`NcComputeHandler`]; the function
/// shows up (transparent) in the `compute/list` dataset.
pub fn register_named_recode(
    service: &ComputeService,
    object: Name,
    generation_id: u64,
    buffer: Arc<Mutex<GenerationBuffer>>,
    kill_switch: Option<Arc<AtomicBool>>,
) {
    let prefix = naming::generation_name(&object, generation_id).append(naming::NC_MARKER);
    let handler = match kill_switch {
        Some(sw) => NcComputeHandler::with_kill_switch(object, generation_id, buffer, sw),
        None => NcComputeHandler::new(object, generation_id, buffer),
    };
    service.register(prefix, handler);
}
