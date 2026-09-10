//! `_nc/<vector>` deterministic recode registered as an ndn-compute function:
//! it appears in the `compute/list` dataset and a consumer fetching named
//! combinations through the compute face recovers the generation. Gated by
//! `f2-recode-compute`.

#![cfg(feature = "f2-recode-compute")]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use ndn_app::{Consumer, EngineBuilder};
use ndn_compute::{ComputeHandler, ComputeService};
use ndn_engine::EngineConfig;
use ndn_face::local::InProcFace;
use ndn_packet::{Interest, Name};

use ndn_coding::policy::Field;
use ndn_coding::recode::{
    CodedMetadata, CodingVector, GenerationBuffer, GenerationDescriptor, RecodePolicy,
    SourceCommitment, naming, row_hash,
};
use ndn_coding::recode_compute::{NcComputeHandler, register_named_recode};

#[tokio::test]
async fn nc_registered_as_compute_function() {
    let k: u16 = 4;
    let symbol_size: u32 = 32;
    let payload: Vec<u8> = (0..(k as usize * symbol_size as usize))
        .map(|i| ((i * 5 + 2) & 0xff) as u8)
        .collect();
    let sources: Vec<Vec<u8>> = payload
        .chunks(symbol_size as usize)
        .map(|c| c.to_vec())
        .collect();

    let object: Name = "/test/nc/compute".parse().unwrap();
    let generation_id = 4u64;
    let descriptor = GenerationDescriptor {
        generation_id,
        k,
        symbol_size,
        field: Field::Gf8,
        content_name: object.clone(),
        source_commitment: SourceCommitment::RowHashes(
            sources.iter().map(|r| row_hash(r)).collect(),
        ),
        recode: RecodePolicy::Open,
        delegation: None,
        fingerprint: None,
    };

    // Seed a full-rank buffer the compute handler will recode from.
    let buffer = Arc::new(Mutex::new(GenerationBuffer::new(descriptor)));
    {
        let mut buf = buffer.lock().unwrap();
        for (i, row) in sources.iter().enumerate() {
            let meta = CodedMetadata {
                generation_id,
                k,
                field: Field::Gf8,
                vector: CodingVector::unit(k, i as u16),
            };
            buf.absorb(&meta, Bytes::from(row.clone())).unwrap();
        }
    }

    let mut builder = EngineBuilder::new(EngineConfig::default());
    let consumer_id = builder.alloc_face_id();
    let (consumer_face, consumer_handle) = InProcFace::new(consumer_id, 256);
    builder = builder.face(consumer_face);
    let (engine, shutdown) = builder.build().await.expect("engine build");

    let service = ComputeService::attach(&engine);
    register_named_recode(
        &service,
        object.clone(),
        generation_id,
        Arc::clone(&buffer),
        None,
    );

    // It shows up in the compute/list dataset, under the _nc prefix.
    let nc_prefix = naming::generation_name(&object, generation_id).append(naming::NC_MARKER);
    assert!(
        service.functions().iter().any(|f| f.prefix == nc_prefix),
        "named recode appears in compute/list"
    );

    // A consumer naming the K unit vectors recovers the sources via compute.
    let mut consumer = Consumer::from_handle(consumer_handle);
    let mut out = GenerationBuffer::new(GenerationDescriptor {
        generation_id,
        k,
        symbol_size,
        field: Field::Gf8,
        content_name: object.clone(),
        source_commitment: SourceCommitment::RowHashes(
            sources.iter().map(|r| row_hash(r)).collect(),
        ),
        recode: RecodePolicy::Open,
        delegation: None,
        fingerprint: None,
    });
    for i in 0..k {
        let target = CodingVector::unit(k, i);
        let name = naming::vector_request_name(&object, generation_id, &target);
        let data = tokio::time::timeout(Duration::from_millis(300), consumer.fetch(name))
            .await
            .expect("no timeout")
            .expect("compute fetch ok");
        let (meta, row) = CodedMetadata::split(data.content().unwrap()).unwrap();
        assert_eq!(meta.vector, target);
        out.absorb(&meta, row).ok();
    }
    assert!(out.is_decodable());
    assert_eq!(out.decode().unwrap().as_ref(), payload.as_slice());

    service.shutdown();
    drop(consumer);
    drop(engine);
    shutdown.shutdown().await;
}

/// Seed a full-rank generation buffer with the given recode policy — enough for the compute handler
/// to mint an exact combination (so anything that still refuses is a GATE, not a lack of rank).
fn seed_full_rank(recode: RecodePolicy) -> (Name, u64, u16, Arc<Mutex<GenerationBuffer>>) {
    let k: u16 = 4;
    let symbol_size: u32 = 32;
    let object: Name = "/test/nc/gate".parse().unwrap();
    let generation_id = 7u64;
    let sources: Vec<Vec<u8>> = (0..k as usize)
        .map(|s| {
            (0..symbol_size as usize)
                .map(|i| ((s * 7 + i) & 0xff) as u8)
                .collect()
        })
        .collect();
    let descriptor = GenerationDescriptor {
        generation_id,
        k,
        symbol_size,
        field: Field::Gf8,
        content_name: object.clone(),
        source_commitment: SourceCommitment::RowHashes(
            sources.iter().map(|r| row_hash(r)).collect(),
        ),
        recode,
        delegation: None,
        fingerprint: None,
    };
    let buffer = Arc::new(Mutex::new(GenerationBuffer::new(descriptor)));
    {
        let mut buf = buffer.lock().unwrap();
        for (i, row) in sources.iter().enumerate() {
            let meta = CodedMetadata {
                generation_id,
                k,
                field: Field::Gf8,
                vector: CodingVector::unit(k, i as u16),
            };
            buf.absorb(&meta, Bytes::from(row.clone())).unwrap();
        }
    }
    (object, generation_id, k, buffer)
}

/// The compute-framed recode must honour the operator's runtime kill switch (doctrine §5) — exactly
/// as the native `RecoderFace` does. Sharing the switch is the whole point: flipping it off must stop
/// EVERY realization of the name, not leave the compute path minting.
#[tokio::test]
async fn compute_recode_honours_the_kill_switch() {
    let (object, gen_id, k, buffer) = seed_full_rank(RecodePolicy::Open);
    let sw = Arc::new(AtomicBool::new(true));
    let handler =
        NcComputeHandler::with_kill_switch(object.clone(), gen_id, buffer, Arc::clone(&sw));
    let name = naming::vector_request_name(&object, gen_id, &CodingVector::unit(k, 0));
    let interest = Interest::new(name);

    assert!(
        handler.handle(&interest).await.is_ok(),
        "enabled + full rank ⇒ the compute path mints"
    );
    sw.store(false, Ordering::Relaxed); // operator pulls the shared kill switch
    assert!(
        handler.handle(&interest).await.is_err(),
        "kill switch off ⇒ the compute path refuses too (no bypass)"
    );
}

/// …and it must honour the per-generation `RecodePolicy::None` (recoding forbidden), which the native
/// path enforces in `mint_exact`. A forbidden generation is refused even at full rank.
#[tokio::test]
async fn compute_recode_honours_policy_none() {
    let (object, gen_id, k, buffer) = seed_full_rank(RecodePolicy::None);
    let handler = NcComputeHandler::new(object.clone(), gen_id, buffer);
    let name = naming::vector_request_name(&object, gen_id, &CodingVector::unit(k, 0));
    let interest = Interest::new(name);
    assert!(
        handler.handle(&interest).await.is_err(),
        "RecodePolicy::None ⇒ the compute path refuses to recode"
    );
}
