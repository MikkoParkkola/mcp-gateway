# Scratch-only B: parse and hash the delivered answer once per replay.
p='src/security/firewall/collusion_gate_replay.rs'; s=open(p).read()
anchor="    pub(crate) fn keep_replayed_digest("
assert s.count(anchor)==1
batch='''    /// PROBE B (scratch): one parse and one hash for every replayed digest.
    pub(crate) fn keep_replayed_batch(
        &self,
        items: Vec<(DeliveryDigest, Option<u32>)>,
        answer: &Value,
        stored_digest: Option<&str>,
    ) -> Vec<Option<DeliveryDigest>> {
        let Some(detector) = self.relay_detector() else {
            return items.into_iter().map(|_| None).collect();
        };
        let (leaves, values) = delivery_parts(answer);
        let Some(delivered) = Delivered::of_parts(leaves, values) else {
            return items.into_iter().map(|_| None).collect();
        };
        let delivered = delivered.with_answer(answer);
        let identical = stored_digest
            .is_some_and(|stored| stored == crate::hashing::canonical_json_sha256(answer));
        items
            .into_iter()
            .map(|(digest, step)| {
                let (kept, dropped) = digest.kept_to_replay_answer(detector, &delivered, identical, step);
                if dropped {
                    count_replay_skipped("filtered");
                }
                Some(kept)
            })
            .collect()
    }

'''
s=s.replace(anchor,batch+anchor); open(p,'w').write(s)
p='src/gateway/meta_mcp/invoke/relay_delivered.rs'; s=open(p).read()
old='''    let stored = super::replay::stored_answer_digest();
    let mut kept: Vec<super::Receipt> = Vec::with_capacity(receipts.len());
    for mut r in receipts.drain(..) {
        if r.kind == super::Kind::Replayed && !r.in_plan {
            let digest = std::mem::take(&mut r.digest);
            let Some(digest) = fw.keep_replayed_digest(digest, answer, stored.as_deref(), r.step)
            else {
                continue;
            };
            r.digest = digest;
            r.pending_retain = false;
        }
        kept.push(r);
    }
    *receipts = kept;
'''
assert s.count(old)==1
new='''    let stored = super::replay::stored_answer_digest();
    let idx: Vec<usize> = receipts
        .iter()
        .enumerate()
        .filter(|(_, r)| r.kind == super::Kind::Replayed && !r.in_plan)
        .map(|(i, _)| i)
        .collect();
    let items = idx
        .iter()
        .map(|&i| (std::mem::take(&mut receipts[i].digest), receipts[i].step))
        .collect();
    let out = fw.keep_replayed_batch(items, answer, stored.as_deref());
    let mut gone = vec![false; receipts.len()];
    for (&i, o) in idx.iter().zip(out) {
        match o {
            Some(d) => {
                receipts[i].digest = d;
                receipts[i].pending_retain = false;
            }
            None => gone[i] = true,
        }
    }
    let mut j = 0;
    receipts.retain(|_| {
        let keep = !gone[j];
        j += 1;
        keep
    });
'''
open(p,'w').write(s.replace(old,new))
print("B planted")
