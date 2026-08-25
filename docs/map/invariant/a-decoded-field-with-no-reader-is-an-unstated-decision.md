# A decoded field with no reader is an unstated decision

## The fact

When a decoder parses a wire field **whose legal values the spec fixes** into a struct
field that no production code reads, the repo has silently taken a position — *we do not
check this* — without recording that it took one. The next person cannot tell a deliberate
tolerance from an oversight, because both look identical: a `pub` field, a doc-comment
naming what the value must be, and no reader.

The fact is **not** "the field is unused". It is "**the field is unread and nothing says
whether that is a decision**".

The counter-example is what makes that a real distinction rather than a complaint about
dead code. `ShareDataHeader::uncompressed_length`
([`share.rs`](../../../crates/justrdp-pdu/src/share.rs)) has zero readers too, and carries
*"informational; decoders should not validate against it (server implementations disagree
on whether headers are included)"*. That is a recorded decision, so it is not an instance —
a reader arriving at it learns why nobody checks it and moves on. `LicensePreamble::msg_size`
is the identical shape (a declared length, never compared to the actual body) with **no note
at all**, and that one is an instance.

## Why it is cross-cutting

It is a property of *how a PDU crate meets its consumers*, not of any protocol layer, so it
recurs wherever `justrdp-pdu` publishes a struct and `justrdp` decides what to do with it.
Three separate passes hit it in three different territories before anyone named it, which is
the recurrence pattern this layer exists to end.

It also has teeth that a style rule would not. [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md)
§1 puts *protocol downgrade* and *unannounced compression* on the strict side, and two of the
instances below are exactly those two classes — decoded, and unchecked. So the unstated
decision is not always "harmless tolerance"; sometimes it is a rule the project already
wrote, unapplied.

## Territories it holds in

- [Capability exchange & activation](../territory/capability-exchange-activation.md) — the
  discovery site. `Synchronize.messageType` was discarded under a doc-comment claiming
  *"ignored per spec"* that the spec does not support, and a server `Control.action` was
  decoded and dropped, making `CTRLACTION_DETACH` indistinguishable from
  `CTRLACTION_GRANTED_CONTROL`. Both closed by #252; both references reject them and justrdp
  was the sole outlier.
- [Session loop & PDU dispatch](../territory/session-loop-dispatch.md) /
  [PDU constants & flag tables](../territory/pdu-constants.md) —
  `ShareDataHeader.compressed_type` states *"must be 0 here: compression is never advertised
  by this client"* and has no reader, while `dvc.rs` rejects the identical violation class
  with a typed error and a test. Open as **#253**. `compressed_length` and `stream_id` are the
  same header, same shape.
- [MCS, GCC & channel setup](../territory/mcs-gcc-channel-setup.md) —
  `ServerCoreData.client_requested_protocols` is the server's echo of what *we* asked for, and
  nothing compares it. A mismatch is downgrade evidence, and `connect.rs` already rejects a
  *selected* protocol we never advertised — the same class, enforced one hop away.
- [Licensing](../territory/licensing.md) — `LicensePreamble.flags` (low nibble is the protocol
  version) and `msg_size` (preamble + body length, an untrusted length never checked against
  the actual body) have no readers anywhere, tests included.

## What a violation looks like

```rust
/// `compressedType` — must be 0 here: compression is never advertised by this client.
pub compressed_type: u8,
```

A doc-comment that states an invariant, a decoder that parses the field, and a `grep` for
`.compressed_type` outside the defining module that returns nothing. The doc-comment is the
tell: it is doing the job a check would do, in a place the compiler cannot reach.

Three ways out, and the point of the invariant is that **any of them is fine and none of them
is silence**:

1. **Enforce it** — a typed error at the consumption site, the way `dvc.rs` does for
   unannounced compression and `Control::check_server_action` does for a server's control action.
2. **Record why not** — a sentence in the field's doc, the way `uncompressed_length` does.
3. **Stop decoding it** — if nothing reads it and nothing should, the field is not carrying
   information.

## Discovery history

- **#242** (2026-08-25) — the completeness pass over the Font Map body found
  `ShareDataHeader.compressed_type` asserting *"must be 0"* with no reader, and noticed
  `dvc.rs` rejecting the same class. Filed as **#253**, framed as one site.
- **#252** (2026-08-25) — the finalization pass found two more in a different territory:
  `Synchronize.messageType` (discarded under a spec citation the spec does not make — the
  spec's MUST-ignore field is `targetUser`, the reverse) and a server `Control.action`
  (decoded, dropped, and fatal in **both** reference implementations). Measured on the real
  VM: the server sends spec-exact values for both on every activation, so the check costs the
  proven server nothing. Closed in the same change.
- **#252's sweep** — a mechanical pass over all 252 `pub` fields of `justrdp-pdu` structs,
  ranked by reader count, turned up three more in two further territories, including the
  `gcc.rs` downgrade-evidence case. **Three passes, three territories, six sites, and the
  first two were each filed as if they were the only one.** That is what promoted it.

## Where it will recur

Any new `pub` field on a `justrdp-pdu` struct whose doc-comment names a value the spec fixes.
The mechanical half of the test:

```sh
# every pub field of a justrdp-pdu struct that no production code reads
rg -n '^\s*pub (\w+):' crates/justrdp-pdu/src --no-heading \
  | while read -r hit; do
      f=${hit##*pub }; f=${f%%:*}
      n=$(rg -c "\.$f\b" crates/*/src 2>/dev/null | wc -l)
      [ "$n" = "0" ] && echo "$hit"
    done
```

The adjudication is by hand and is two questions, in this order: **does the field's
doc-comment state a value the spec fixes?** If no, it is ordinary unused data and this note
does not apply. If yes, **does anything say why nobody checks it?** If no, that is an
instance — pick one of the three ways out above.

Reading the count alone is the trap: a field with one reader can still be an instance if that
reader is a test, and `stream_id`, `compressed_type` and `compressed_length` are all exactly
that — read only by `share.rs`'s own round-trip assertions, which check what our encoder wrote
rather than what a server sent.
