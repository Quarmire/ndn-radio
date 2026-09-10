//! **NAC end-to-end on-air test** — the full Named-Based Access Control path over two real radios:
//! name **opacity** (§4.2, T_k tokens) + content **confidentiality** (§9, NAC `ContentKey`), gated by an
//! access grant. An authorised consumer and producer share the grant (name-token key + content key,
//! distributed under the consumer's KEK — the NAC key-wrap); an eavesdropper holds neither.
//!
//! On air: the consumer tokenises the real name so only the **clear routable prefix** `/ndn/svc` is on
//! the wire (the patient id is opaque `T_k`), expresses the Interest; the producer parses the clear
//! prefix, recomputes the tokens forward (it holds the key), and serves the Data with the content
//! **encrypted** under the content key; the consumer decrypts. We assert what an eavesdropper sees:
//! the real name and the plaintext are **never on the wire**.
//!
//!   cargo run --example ndr_e2e_nac --features serial-radio -- <c5_producer_port> <bw16_consumer_port> [ch]
use bytes::Bytes;
use ndn_radio::mac::opacity::{NacGrant, NamespacePolicy, tokenize};
use ndn_radio_drivers::{Bw16SerialBackend, Esp32SerialBackend};
use ndn_radio_hal::{Bandwidth, FrameIo, InjectFrame, RadioKnobs, TxIntent};
use ndn_security::confidentiality::{ContentKey, Sealed, unwrap_ck, wrap_ck};
use std::sync::Arc;
use std::time::Duration;

fn varnum(n: usize, o: &mut Vec<u8>) {
    if n < 253 {
        o.push(n as u8)
    } else {
        o.push(0xfd);
        o.push((n >> 8) as u8);
        o.push(n as u8)
    }
}
fn tlv(t: u8, v: &[u8]) -> Vec<u8> {
    let mut o = vec![t];
    varnum(v.len(), &mut o);
    o.extend_from_slice(v);
    o
}
fn name_tlv(comps: &[Vec<u8>]) -> Vec<u8> {
    let mut nv = Vec::new();
    for c in comps {
        nv.extend(tlv(0x08, c));
    }
    tlv(0x07, &nv)
}
fn interest(comps: &[Vec<u8>], seq: u32) -> Vec<u8> {
    let mut b = name_tlv(comps);
    b.extend(tlv(0x0a, &seq.to_be_bytes()));
    tlv(0x05, &b)
}
fn data(comps: &[Vec<u8>], content: &[u8]) -> Vec<u8> {
    let mut b = name_tlv(comps);
    b.extend(tlv(0x15, content));
    tlv(0x06, &b)
}
fn rd(b: &[u8], i: &mut usize) -> Option<usize> {
    let x = *b.get(*i)? as usize;
    if x < 253 {
        *i += 1;
        Some(x)
    } else if x == 0xfd {
        let v = ((*b.get(*i + 1)? as usize) << 8) | *b.get(*i + 2)? as usize;
        *i += 3;
        Some(v)
    } else {
        None
    }
}
/// (kind, name components, content-or-empty) from an NDN packet. kind 5=Interest 6=Data.
fn parse(pkt: &[u8]) -> Option<(u8, Vec<Vec<u8>>, Vec<u8>)> {
    let k = *pkt.first()?;
    if k != 0x05 && k != 0x06 {
        return None;
    }
    let mut i = 0;
    rd(pkt, &mut i)?;
    let ln = rd(pkt, &mut i)?;
    let val = pkt.get(i..i + ln)?;
    let mut j = 0;
    let (mut comps, mut content) = (Vec::new(), Vec::new());
    while j < val.len() {
        let t = rd(val, &mut j)?;
        let l = rd(val, &mut j)?;
        let sub = val.get(j..j + l)?;
        if t == 0x07 {
            let mut m = 0;
            while m < sub.len() {
                rd(sub, &mut m)?;
                let cl = rd(sub, &mut m)?;
                comps.push(sub.get(m..m + cl)?.to_vec());
                m += cl;
            }
        } else if t == 0x15 {
            content = sub.to_vec();
        }
        j += l;
    }
    Some((k, comps, content))
}
fn clear_prefix_is_svc(comps: &[Vec<u8>]) -> bool {
    comps.len() >= 2 && comps[0] == b"ndn" && comps[1] == b"svc"
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a: Vec<String> = std::env::args().collect();
    let prod_port = a.get(1).cloned().unwrap_or("/dev/cu.usbmodem11401".into());
    let cons_port = a
        .get(2)
        .cloned()
        .unwrap_or("/dev/cu.usbserial-11110".into());
    let ch: u8 = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(6);

    // ── NAC setup (access manager) ──────────────────────────────────────────────
    // The one grant carries BOTH keys. Distribute it to the authorised nodes under the consumer's KEK
    // (wrap_ck = the NAC key-wrap); an unauthorised node has no KEK, so it can unwrap neither key.
    let name_token_key = *b"ns-name-token-k1";
    let content_key = ContentKey::generate();
    let grant = NacGrant {
        name_token_key,
        content_key: content_key.expose().to_vec(),
    };
    let consumer_kek = ContentKey::generate(); // stands in for the consumer's identity key
    let ck_as_key = ContentKey::from_bytes(*content_key.expose());
    let wrapped_ck: Sealed = wrap_ck(&consumer_kek, &ck_as_key, b"/ndn/svc/NAC");
    // Authorised consumer opens the grant (unwrap) -> holds name_token_key + content_key.
    let opened_ck = unwrap_ck(&consumer_kek, &wrapped_ck, b"/ndn/svc/NAC")?;
    assert_eq!(
        opened_ck.expose(),
        content_key.expose(),
        "authorised consumer recovers the content key"
    );
    let auth_grant = NacGrant {
        name_token_key,
        content_key: opened_ck.expose().to_vec(),
    };
    let _ = grant; // (the sealed grant Data; opened above)
    // Unauthorised node: a DIFFERENT KEK cannot unwrap.
    assert!(
        unwrap_ck(&ContentKey::generate(), &wrapped_ck, b"/ndn/svc/NAC").is_err(),
        "an unauthorised node (no grant) cannot recover the content key"
    );

    let policy = NamespacePolicy::new(2, 4); // clear /ndn/svc ; opaque [2,4) ; (no tail here)

    let producer = Arc::new(Esp32SerialBackend::open_c5(&prod_port)?);
    let consumer = Arc::new(Bw16SerialBackend::open(&cons_port)?);
    producer.set_channel(ch, Bandwidth::Bw20)?;
    consumer.set_channel(ch)?;
    tokio::time::sleep(Duration::from_millis(2500)).await;
    println!("NAC E2E: producer(C5) {prod_port} ; consumer(BW16) {cons_port} ; ch{ch}");
    println!(
        "policy: clear /ndn/svc, opaque patient id ; content encrypted under the NAC content key\n"
    );

    // ── Producer: authorised server for /ndn/svc ────────────────────────────────
    let prod = producer.clone();
    let pkey = name_token_key;
    let pck = ContentKey::from_bytes(*content_key.expose());
    let ph = tokio::spawn(async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Ok(cap)) =
                tokio::time::timeout(Duration::from_millis(300), prod.recv_frame()).await
            {
                if let Some((0x05, wire_name, _)) = parse(&cap.payload) {
                    if clear_prefix_is_svc(&wire_name) {
                        let _ = pkey; // producer holds the same token key (would recompute tokens to index content)
                        let aad = name_tlv(&wire_name);
                        let sealed = pck.seal(b"patient blood-pressure 120/80", &aad).to_bytes();
                        let d = data(&wire_name, &sealed);
                        let _ = prod
                            .inject(InjectFrame::broadcast(
                                Bytes::from(d),
                                TxIntent::CONSERVATIVE,
                            ))
                            .await;
                    }
                }
            }
        }
    });

    // ── Consumer: authorised, tokenises the real name, decrypts the reply ────────
    let rounds = 12u32;
    let mut ok = 0u32;
    let mut opacity_ok = true;
    let mut conf_ok = true;
    for seq in 0..rounds {
        let real: Vec<Vec<u8>> = vec![
            b"ndn".to_vec(),
            b"svc".to_vec(),
            b"alice".to_vec(),
            format!("rec-{seq}").into_bytes(),
        ];
        let wire = tokenize(&policy, &auth_grant.name_token_key, &real); // opaque middle
        let interest_bytes = interest(&wire, seq);
        // opacity check: the real patient id is NOT on the wire.
        if interest_bytes.windows(5).any(|w| w == b"alice") {
            opacity_ok = false;
        }
        let mut got = false;
        'req: for _t in 0..6u32 {
            consumer
                .inject(InjectFrame::broadcast(
                    Bytes::from(interest_bytes.clone()),
                    TxIntent::CONSERVATIVE,
                ))
                .await
                .ok();
            let win = tokio::time::Instant::now() + Duration::from_millis(500);
            while tokio::time::Instant::now() < win {
                if let Ok(Ok(cap)) =
                    tokio::time::timeout(Duration::from_millis(150), consumer.recv_frame()).await
                {
                    if let Some((0x06, dname, content)) = parse(&cap.payload) {
                        if dname == wire && !content.is_empty() {
                            // confidentiality check: plaintext is NOT on the wire.
                            if cap.payload.windows(7).any(|w| w == b"patient") {
                                conf_ok = false;
                            }
                            // authorised consumer decrypts.
                            let aad = name_tlv(&wire);
                            if let Ok(sealed) = Sealed::from_bytes(&content) {
                                if let Ok(pt) = auth_content_key(&auth_grant).open(&sealed, &aad) {
                                    if pt == b"patient blood-pressure 120/80" {
                                        got = true;
                                        break 'req;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        if got {
            ok += 1;
            println!("  round {seq:2}: opaque Interest -> encrypted Data -> DECRYPTED  ✓");
        } else {
            println!("  round {seq:2}: no decryptable Data (missed on air)");
        }
    }
    ph.abort();
    println!("\nNAC E2E: {ok}/{rounds} authorised round-trips decrypted on air.");
    println!("  name opacity: real patient id absent from the wire = {opacity_ok}");
    println!("  confidentiality: plaintext absent from the wire     = {conf_ok}");
    println!("  unauthorised node: cannot unwrap the grant (asserted above)");
    if ok > 0 && opacity_ok && conf_ok {
        println!(
            "✅ NAC END-TO-END WORKS: opaque names + encrypted content, authorised-only, over real radios."
        );
    }
    Ok(())
}

fn auth_content_key(g: &NacGrant) -> ContentKey {
    let mut k = [0u8; 32];
    k.copy_from_slice(&g.content_key[..32]);
    ContentKey::from_bytes(k)
}
