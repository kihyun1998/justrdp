# Device redirection

## What it is

The `rdpdr` static channel (`[MS-RDPEFS]`): the client announces devices, and the server
drives them with Device I/O Requests (IRPs) that the client completes. `justrdp-pdu::rdpdr`
holds the PDUs and `justrdp::rdpdr::DeviceRedirection` is a sans-IO helper the host drives,
as `cliprdr::Clipboard` is: the host feeds it each message received on the channel and sends
what it returns. Only drives are redirected (#13); printers, smartcards, serial ports and USB
are not. The helper completes the initialization sequence and announces the host's drives
(#336), and the server can open, describe and list a drive's folders (#337); reading,
writing and adding or removing drives are #338-#340.

## Governing decisions

- [ADR-0001](../../adr/0001-sans-io-state-machine-core.md) — the helper is sans-IO, and the
  Amendment's tree rule puts the PDUs in `justrdp-pdu/src/rdpdr.rs` and the helper in
  `justrdp/src/rdpdr.rs`, beside `cliprdr`.
- [ADR-0009](../../adr/0009-tolerant-negotiation-posture.md) — tolerant of a server's
  inconsistencies, strict on security; a path escaping a drive falls on the strict side.
- **The #13 grill (2026-09-28)**, recorded in #13's body: drive only; the core enforces wire
  invariants and the host owns policy; IRPs reach the host as events answered by
  `CompletionId`; no filesystem backend ships. Those are the maintainer's calls.
- **Ending the channel on a message it cannot read was the maintainer's call (2026-09-28,
  #336)**, made after they were shown `[MS-RDPEFS]` 3.1.5.2 ("SHOULD terminate the virtual
  channel connection"). It replaced the grill's first answer, the clipboard's precedent,
  which had been chosen without that text. The alternatives shown were keeping the
  clipboard's precedent and ending the whole session.
- **Paging and matching a directory in the core was the maintainer's call (2026-09-28,
  #337).** Shown: the host answers a whole listing once and the core filters it by the
  server's pattern and hands out one entry per query, so every host gets the same wildcard
  meaning; or the host takes each query with its pattern and answers one entry, as IronRDP's
  Windows backend does with the OS's own matching.
- **Refusing the reserved device names in the core was the maintainer's call (2026-09-28,
  #337)**, made after they were shown 3.2.5.2.3 ("MUST be completed with
  STATUS_ACCESS_DENIED"). The grill had given device names to the host without that text.
  The call covers a Create whose whole path is one of those names; the same name deeper in a
  path, and every other OS name rule, stay the host's.

## Design model

- **The sequence** (1.3.1). Server Announce is answered with Client Announce Reply and Client
  Name. Server Core Capability Request is answered at once (3.2.5.1.8) with General and Drive
  capability sets. Server Client ID Confirm must carry the reply's `ClientId` (3.2.5.1.6).
  Drives are announced once, on User Logged On, as IronRDP and FreeRDP do; 3.2.5.1.9 would
  also allow announcing earlier.
- **Version and `ClientId`.** The client sends the highest version it knows (0x0D) not above
  the server's. From server version 12 it echoes the server's `ClientId`; below it, 3.2.5.1.3
  requires a random one, and the sans-IO core has no randomness, so the host passes one to
  `DeviceRedirection::new`, as it passes `LicenseEntropy`.
- **What is advertised.** `ioCode1` is 0x3FFF: bits 0x1-0x2000 are "Unused, always set"
  (2.2.2.7.1), so they gate nothing, and the two security bits stay clear. `extendedPDU` sets
  User Logged On and the always-set display-name bit; Device List Remove waits for #340.
  `ENABLE_ASYNCIO` is not advertised, as in IronRDP, so requests on one file stay sequential.
  No printer, port or smartcard set is sent, which 1.7 reads as not supported.
- **The server's capability sets are decoded and not read yet.** Its `extendedPDU` Device
  List Remove bit is what #340 will read before sending a removal; `osType` and `osVersion`
  are ones 2.2.2.7.1 says to ignore. Nothing else in them changes what this client sends.
- **A drive's name** goes in full into `DeviceData` and cut to seven ASCII characters into
  `PreferredDosName`. **`DeviceData` is ASCII, not the UTF-16 2.2.3.1 names**: WS2022 reads
  it as 8-bit characters, so a UTF-16 name registers as its first letter (measured below).
  FreeRDP sends ASCII; IronRDP sends UTF-16. The helper refuses a name that is empty, not
  ASCII, holds a NUL or one of `< > " / \ |`, or has a `:` before its end (2.2.1.3), and two
  drives with one `device_id`.
- **The host answers facts; the helper speaks the wire.** A Create reaches the host as
  `DriveRequest::Open`, Query Volume Information as `QueryVolume`, Query Information as
  `QueryInformation`, and a first Query Directory as `ListDirectory`. The host answers with
  `respond_open`, `respond_volume`, `respond_information` or `respond_listing`, by
  `CompletionId` and in any order, with typed values (`Opened`, `VolumeInformation`,
  `FileInformation`, `DirectoryEntry`) or an NTSTATUS; the helper encodes the `[MS-FSCC]`
  structures. An answer of the wrong kind, or for no waiting request, is refused
  (`RespondError`) and the request keeps waiting.
- **The helper owns the file IDs.** A Create is given the next free nonzero `FileId` before
  it reaches the host, and later requests name the file by it. A Close is answered by the
  helper: it forgets the file, answers what the host still owes about it
  `STATUS_CANCELLED` (3.2.5.2.5), and reports `FileClosed`. So does a new Server Announce or
  the channel ending, for every open file.
- **A Create's `Information`** comes from its disposition, by the 2.2.1.5.1 table: `FILE_OPEN_IF`
  is `FILE_OPENED`, `FILE_OVERWRITE_IF` is `FILE_OVERWRITTEN`, and the rest
  `FILE_SUPERSEDED`, as FreeRDP does. IronRDP's Windows backend passes on what the OS
  reports. An unknown disposition is `STATUS_INVALID_PARAMETER`.
- **Paths are checked against the wire before the host sees them.** The helper splits a path
  on `\` and drops empty components, so `""` and `\` are the root. A path that is not UTF-16,
  or has a component that is `.` or `..` or holds a NUL, `/` or `:`, is
  `STATUS_OBJECT_NAME_INVALID`: `/` would be a separator to a POSIX host and `:` names a
  drive letter or a stream. A Create whose whole path is a reserved device name (3.2.5.2.3,
  case ignored) is `STATUS_ACCESS_DENIED`. IronRDP's nix backend checks none of this.
- **A directory is listed in the core.** A first Query Directory splits its path into the
  directory and a pattern (`*` when the path is only the directory) and asks the host for
  every entry; the helper keeps the entries the pattern matches and answers with the first,
  or `STATUS_NO_SUCH_FILE` when none does. A later query takes the next, then
  `STATUS_NO_MORE_FILES` (2.2.3.3.10). One entry per response with `NextEntryOffset` zero, as
  FreeRDP sends. Matching ignores case and follows `[MS-FSA]` 2.1.4.4: `*`, `?`, and the DOS
  wildcards `<`, `>` and `"`, in one pass over the name per pattern character: the pattern
  is server-sized, and filling from every reachable position made a 400,000-character one
  take 10.5 s against 0.33 s. A Query Directory on a file is `STATUS_NOT_A_DIRECTORY`; a
  change notification is `STATUS_NOT_SUPPORTED`, as FreeRDP answers it.
- **Only the classes the server was measured to use are implemented**: Query Volume
  Information `FileFsVolumeInformation` (1), `FileFsAttributeInformation` (5) and
  `FileFsFullSizeInformation` (7); Query Information `FileBasicInformation` (4) and
  `FileStandardInformation` (5); Query Directory `FileFullDirectoryInformation` (2) and
  `FileBothDirectoryInformation` (3). Any other class is `STATUS_NOT_SUPPORTED` without the
  host, among them the ones FreeRDP also implements: `FileFsSizeInformation` (3),
  `FileFsDeviceInformation` (4), `FileAttributeTagInformation` (0x23),
  `FileDirectoryInformation` (1) and `FileNamesInformation` (0xC). The `Reserved` fields
  2.2.3.3.6, 2.2.3.3.8 and 2.2.3.3.10 exclude are left out: Volume has 17 bytes before its
  label, Basic is 36 bytes, Standard 22, and a Both entry's name starts at 93.
- **What waits is bounded**: at most `MAX_PENDING_REQUESTS` (100, #331's shape) requests
  wait for the host, and one past it is `STATUS_INSUFFICIENT_RESOURCES`; a `CompletionId`
  already waiting is `STATUS_UNSUCCESSFUL`. At most `MAX_OPEN_FILES` (1024) files are open,
  counting Creates the host has not answered, and a Create past it is
  `STATUS_TOO_MANY_OPENED_FILES`. A directory's listing is held until its next first query or
  its Close, and is as long as the host made it.
- **Every other IRP is refused until its slice lands.** A major function 2.2.1.4 defines gets
  `STATUS_NOT_SUPPORTED`, as both references answer the ones they do not implement; any other
  gets `STATUS_UNSUCCESSFUL`, which 3.1.5.2 asks for. A failed completion carries the fields
  its response layout has, zeroed: a Create's `FileId` and `Information`, a Write's or
  Directory Control's `Length` and padding, a Close's or Lock's padding, every other known
  response's `Length`. An IRP for a device not announced is ignored (3.1.5.2), and one whose
  header reads but whose body does not is `STATUS_UNSUCCESSFUL` and the channel goes on.
- **A message the helper cannot read ends the channel** (3.1.5.2): one that does not decode,
  an unknown `Component` or `PacketId`, or a Client ID Confirm for another `ClientId`. The
  helper reports `Terminated` once and ignores everything after, a new Server Announce
  included; the session goes on, since a static channel cannot be closed alone. A message
  that arrives before Server Announce is skipped instead, which 3.1.5.2 allows.
- **A later Server Announce starts over** (3.2.5.1.2): the drives are announced again after
  the next User Logged On.
- **`rdpsnd` must be requested too.** `[MS-RDPEFS]` 2.1 footnote 1: the server does not use
  `rdpdr` unless the client advertises `RDPSND`. Which channels to request is the host's, so
  the helper only says so; nothing has to answer `rdpsnd`.

## Code

- `justrdp-pdu/src/rdpdr.rs` — `RdpdrPdu`, `CapabilitySet`, `GeneralCapability`,
  `IoRequest`, `IoBody`, `CreateRequest`, `DeviceAnnounce`, `FileInformation`,
  `VolumeInformation`, `encode_client_announce_reply`, `encode_client_name`,
  `encode_client_capabilities`, `encode_device_list_announce`, `encode_io_completion`,
  `encode_file_information`, `encode_volume_information`, `encode_directory_entry`,
  `length_prefixed`, `failure_body`, `is_known_major`, `IO_CODE1_ALWAYS_SET`
- `justrdp/src/rdpdr.rs` — `DeviceRedirection`, `DeviceRedirectionOutput`, `DriveRequest`,
  `Opened`, `OpenKind`, `Disposition`, `DirectoryEntry`, `RespondError`, `Drive`,
  `DriveError`, `channel_def`, `MAX_PENDING_REQUESTS`, `MAX_OPEN_FILES`, `drive_path`,
  `matches_pattern`
- `fuzz/fuzz_targets/rdpdr.rs` — `RdpdrPdu`
- `justrdp-tokio/src/lib.rs` — `the_device_redirection_handshake_accepts_a_drive_on_the_real_vm`,
  `the_server_lists_a_host_drive_on_the_real_vm`
- Spec sections cited inline: `[MS-RDPEFS]` 1.3.1, 1.7, 2.1, 2.2.1.3, 2.2.1.4, 2.2.1.5.1-5,
  2.2.2.3, 2.2.2.7.1, 2.2.3.1, 2.2.3.3.6, 2.2.3.3.8, 2.2.3.3.10, 2.2.3.4, 3.1.5.2, 3.2.5.1.2,
  3.2.5.1.3, 3.2.5.1.6, 3.2.5.1.8, 3.2.5.1.9, 3.2.5.2.3, 3.2.5.2.5; `[MS-FSA]` 2.1.4.4

## Reference behaviour

**Measured against the WS2022 test VM (#336, 2026-09-28):**

- The server announces version 13 (0x0D) with `ClientId` 65, and confirms the echoed ID. Its
  capability request holds General version 2 (`protocolMinor` 13, `ioCode1` 0xFFFF,
  `extendedPDU` 7, `SpecialTypeDeviceCap` 2), Printer 1, Port 1, Drive 2 and Smartcard 1.
- User Logged On follows the Client ID Confirm, and the drive is accepted (`STATUS_SUCCESS`).
  **`rdpsnd` requested and never answered is enough**: it sent nothing. ~~A drive named
  `justrdp` is accepted~~ — accepted, but registered as `j`, since #336 sent `DeviceData` as
  UTF-16 (#337). Its test checks acceptance only, so it could not see the name.
- Unprompted, the server then sends three Creates for the drive, one at a time, each under
  `CompletionId` 0. Each was refused `STATUS_NOT_SUPPORTED` and the session went on.
- 3 of 3 runs alike (`ClientId` 65, 66, 67). **With `RDPDR_USER_LOGGEDON_PDU` cleared, the
  server sends a second Client ID Confirm instead of User Logged On**, so the helper never
  announces the drive and the test times out: one run, the mutation that proves the test
  observes the bit.

**Measured against the WS2022 test VM (#337, 2026-09-28):**

- **A UTF-16 `DeviceData` names the share by its first letter.** With `justrdp` sent as
  UTF-16, `\\tsclient\justrdp` is "network name not found" and `net view \\tsclient` fails
  with error 1707, while `cmd /c dir /b \\tsclient\j` lists the drive. With ASCII it is
  `\\tsclient\justrdp`.
- The unprompted opening: three Creates of the root (empty path, `FILE_DIRECTORY_FILE`,
  `DesiredAccess` 0x80), each followed by Query Information `FileBasicInformation` and, for
  two of them, `FileStandardInformation`, then a Close. A failed `\\tsclient` lookup sends
  no IRP at all.
- `Get-ChildItem -Recurse` lists the in-memory tree exactly: names, sizes, and `sub` as a
  folder. It uses Create, Close, Query Information 4 and 5, and Query Directory 3. `cmd /c
  dir` of `sub` adds Query Volume Information 1, 5 and 7 and Query Directory 2, and prints
  the label, the serial `1D00-5EED` and 2,147,483,648 bytes free, as the host gave them. The
  root was also opened as `\` (`DesiredAccess` 0x100000 and 0x100001, `CreateOptions` 0x21).
  84 requests per run, 3 of 3 runs alike.
- No `.` or `..` entry is needed: the host lists neither and both listings are complete.

## Cross-cutting invariants

- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md)
  — `extendedPDU`'s User Logged On bit is what makes the server send it, and so what makes
  the drives be announced; Device List Remove stays clear until #340 implements it.
- [Untrusted decode never panics](../invariant/untrusted-decode-never-panics.md) — every
  message here is server-supplied; `RdpdrPdu::decode` has a fuzz target and a proptest, and
  a path is decoded from a server-declared length.

## Blast radius

- [Virtual channels](virtual-channels.md) — the static channel transport this rides on, and
  the clipboard helper whose shape this one follows.
- [Verification harness](verification-harness.md) — the VM tests request `rdpsnd` beside
  `rdpdr`, read a listing back over the clipboard, and must let the desktop settle before
  they end the session.

## Known holes / open

- IRPs: reading (#338), writing (#339) and adding or removing drives during a session
  (#340). Until then a file can be opened and described but not read.
- Printer, smartcard, serial and USB redirection are outside #13.
