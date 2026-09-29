# Device redirection

## What it is

The `rdpdr` static channel (`[MS-RDPEFS]`): the client announces devices, and the server
drives them with Device I/O Requests (IRPs) that the client completes. `justrdp-pdu::rdpdr`
holds the PDUs and `justrdp::rdpdr::DeviceRedirection` is a sans-IO helper the host drives,
as `cliprdr::Clipboard` is: the host feeds it each message received on the channel and sends
what it returns. Only drives are redirected (#13); printers, smartcards, serial ports and USB
are not. The helper completes the initialization sequence and announces the host's drives
(#336), the server can open, describe and list a drive's folders (#337), read its files
(#338), and write, rename and delete them (#339), and the host adds and removes drives
during a session (#340).

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
- **Leaving the server's Read `Length` uncapped in the core was the maintainer's call
  (2026-09-29, #338)**, shown the measured sizes (at most 131,072), IronRDP's 1 MiB refusal
  and FreeRDP's trim to the file's end. How much to read at once is the host's.
- **Answering a zero-length Read and one past `MAXLONGLONG` in the core was the maintainer's
  call (2026-09-29, #338)**, made after the change was confirmed, shown `[MS-FSA]` 2.1.5.3 and
  IronRDP's same refusal; the alternative shown was leaving both to the host. The directory
  and not-open answers were part of the confirmed change.
- **Answering a Write past `MAXLONGLONG` in the core was the maintainer's call (2026-09-29,
  #339)**, shown `[MS-FSA]` 2.1.5.4 and that it widened the #338 call on Read, which had not
  covered Write; the alternative shown was leaving it to the host. What they were also shown:
  a zero-length Write still reaches the host, unlike a Read, because 2.1.5.4 refuses a
  read-only volume first.
- **Answering what the host still owes on a removed drive `STATUS_CANCELLED` was the
  maintainer's call (2026-09-29, #340)**, shown IronRDP (cancellations before the Remove)
  and FreeRDP (queued requests discarded with no completion). It covers requests waiting for
  the host when `remove_drive` runs, not ones arriving after.
- **Failing a request that arrives for a removed drive was the maintainer's call
  (2026-09-29, #340)**, made on a measurement: discarded as 3.2.5.2.2 says ("MUST be
  considered invalid and the request will be discarded"), a Query Information on a file the
  server still held open crossed the Remove and its caller hung, 2 of 7 runs; answered
  `STATUS_UNSUCCESSFUL`, 5 of 5 passed, two of them with that same crossing. The
  alternatives shown were discarding, and failing every unknown device as FreeRDP's
  `IgnoreInvalidDevices` does, which would also change the 3.1.5.2 rule for devices never
  announced. **Not covered**: how long to keep answering for a removed ID beyond the next
  Server Announce or its reuse.
- **Moving the VM tests' in-memory host into `drive_host` and giving #340 its own test was
  the maintainer's call (2026-09-29, #340)**; the alternative shown was growing the one
  list/read/write test further.

## Design model

- **The sequence** (1.3.1). Server Announce is answered with Client Announce Reply and Client
  Name. Server Core Capability Request is answered at once (3.2.5.1.8) with General and Drive
  capability sets. Server Client ID Confirm must carry the reply's `ClientId` (3.2.5.1.6).
  The drives held at User Logged On are announced then, as IronRDP and FreeRDP do; 3.2.5.1.9
  would also allow announcing earlier.
- **Version and `ClientId`.** The client sends the highest version it knows (0x0D) not above
  the server's. From server version 12 it echoes the server's `ClientId`; below it, 3.2.5.1.3
  requires a random one, and the sans-IO core has no randomness, so the host passes one to
  `DeviceRedirection::new`, as it passes `LicenseEntropy`.
- **What is advertised.** `ioCode1` is 0x3FFF: bits 0x1-0x2000 are "Unused, always set"
  (2.2.2.7.1), so they gate nothing, and the two security bits stay clear. `extendedPDU` sets
  User Logged On, Device List Remove (since #340) and the always-set display-name bit.
  `ENABLE_ASYNCIO` is not advertised, as in IronRDP, so requests on one file stay sequential.
  No printer, port or smartcard set is sent, which 1.7 reads as not supported.
- **Of the server's capability sets, only the General set's `extendedPDU` is read**: its
  `RDPDR_DEVICE_REMOVE_PDUS` is what allows a removal, and it is forgotten on a new Server
  Announce. `osType` and `osVersion` are ones 2.2.2.7.1 says to ignore; nothing else in them
  changes what this client sends.
- **The host adds and removes drives during a session.** `add_drive` holds a drive to
  `new`'s rules and a free `device_id`; after User Logged On it announces it at once, alone
  (3.2.5.1.9), and before it, with the others then, so a helper that began with no drive
  still announces one. `remove_drive` of an accepted drive answers what the host owes on it
  `STATUS_CANCELLED`, closes its files for the host (`FileClosed`, with its `delete`), then
  sends Client Drive Device List Remove (2.2.3.2); both references cancel or discard before
  removing. A drive whose announcement the server has not answered is removed when the
  server accepts it, as IronRDP defers it, and forgotten if the server refuses; neither
  answer reaches the host. A drive never announced, or one the server refused, is dropped
  with no message. **Removing an announced drive needs the server's
  `RDPDR_DEVICE_REMOVE_PDUS`**: without it `remove_drive` returns
  `RemoveError::NotSupported` and nothing changes, as FreeRDP sends a removal only when
  both sides set the bit. A removed `device_id` may be announced again (2.2.3.2), and a new
  Server Announce re-announces the drives held then.
- **A request for a removed drive is failed, not discarded.** The server can send one before
  it reads the removal, and waits for its completion; the helper keeps the removed IDs until
  their reuse or a new Server Announce and answers them `STATUS_UNSUCCESSFUL`, a Set
  Information repeating its `Length`. A request for a device never announced is still
  ignored (3.1.5.2).
- **A drive's name** goes in full into `DeviceData` and cut to seven ASCII characters into
  `PreferredDosName`. **`DeviceData` is ASCII, not the UTF-16 2.2.3.1 names**: WS2022 reads
  it as 8-bit characters, so a UTF-16 name registers as its first letter (measured below).
  FreeRDP sends ASCII; IronRDP sends UTF-16. The helper refuses a name that is empty, not
  ASCII, holds a NUL or one of `< > " / \ |`, or has a `:` before its end (2.2.1.3), and two
  drives with one `device_id`.
- **The host answers facts; the helper speaks the wire.** A Create reaches the host as
  `DriveRequest::Open`, Query Volume Information as `QueryVolume`, Query Information as
  `QueryInformation`, a first Query Directory as `ListDirectory`, a Read as `Read`, a Write
  as `Write`, and a Set Information as `SetEndOfFile`, `SetAllocationSize`, `SetBasic`,
  `Rename` or `Delete`. The host answers with `respond_open`, `respond_volume`,
  `respond_information`, `respond_listing`, `respond_read`, `respond_write` or
  `respond_set`, by
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
- **A Read hands the host an offset and the most bytes to read**, and the host answers with
  the bytes: fewer at the file's end, or an NTSTATUS such as `STATUS_END_OF_FILE` at or past
  it, which `[MS-FSA]` 2.1.5.3 gives. **An answer longer than the read asked for is refused**
  (`RespondError::TooLong`) and the read keeps waiting, so the server never receives more
  than it asked for. What 2.1.5.3 decides before a file's data is reached the helper answers
  itself: a `Length` of zero is `STATUS_SUCCESS` with nothing read, and an `Offset` plus
  `Length` past `0x7FFFFFFFFFFFFFFF`, a 64-bit overflow included, is
  `STATUS_INVALID_PARAMETER`. A Read of a directory is `STATUS_INVALID_DEVICE_REQUEST`, as
  Wine maps `EISDIR`; one of a file not open is `STATUS_UNSUCCESSFUL`. The request decodes
  from its first 12 bytes, since 2.2.1.4.3's 20 bytes of `Padding` MUST be ignored, as
  FreeRDP reads it. **The server's `Length` is not capped here**: the helper holds only what
  the host answers, so how much to read at once is the host's; IronRDP's Windows backend
  refuses above 1 MiB with `STATUS_INVALID_PARAMETER`, and FreeRDP trims it to what is left
  of the file. A host decides how much to allocate before it reads.
- **A Write hands the host an offset and the data**, and the host answers with how many bytes
  it wrote; **a count above the data's length is refused** (`RespondError::TooLong`). An
  `Offset` of all ones is `WriteOffset::Append` when this client announced version 0x0D or
  later (2.2.1.4.4), and an offset past `MAXLONGLONG` below it. The helper answers a Write to
  a directory (`STATUS_INVALID_DEVICE_REQUEST`), to a file not open (`STATUS_UNSUCCESSFUL`)
  and one reaching past `MAXLONGLONG` (`STATUS_INVALID_PARAMETER`, `[MS-FSA]` 2.1.5.4). **A
  zero-length Write still reaches the host**, unlike a zero-length Read: 2.1.5.4 refuses a
  write on a read-only volume before it answers a zero-length one, and read-only is the
  host's. The response carries the count and one padding byte, as FreeRDP sends it.
- **Set Information reaches the host one class at a time**, by the five 2.2.3.3.9 names:
  `FileEndOfFileInformation` as `SetEndOfFile`, `FileAllocationInformation` as
  `SetAllocationSize`, `FileBasicInformation` as `SetBasic` (raw, with `[MS-FSCC]` 2.4.7's 0,
  -1 and -2), `FileRenameInformation` as `Rename` and `FileDispositionInformation` (an empty
  buffer meaning delete, 2.2.3.3.9) as `Delete`; any other class is `STATUS_NOT_SUPPORTED`.
  All five are implemented, not only the measured ones, since 2.2.3.3.9 closes the list. A
  size on a directory or past `MAXLONGLONG` is `STATUS_INVALID_PARAMETER` (`[MS-FSA]`
  2.1.5.15.5), as IronRDP refuses a negative one. **Every response repeats the request's
  `Length`**, a failed or cancelled one included, since 2.2.3.4.9 says it MUST; FreeRDP does
  the same.
- **A rename target is checked like a Create's path**: split below the drive's root, `.`,
  `..`, a NUL, `/` or `:` refused `STATUS_OBJECT_NAME_INVALID`, and so is the root itself; a
  nonzero `RootDirectory` is `STATUS_INVALID_PARAMETER` (2.2.3.3.9.1 says it MUST be zero).
  Reserved device names are not refused here: 3.2.5.2.3 speaks of a Create.
- **A delete happens when the file closes**, as it does in NT. The helper marks the file when
  the host accepts a `Delete` (unmarks it on `delete: false`) or when its Create carried
  `FILE_DELETE_ON_CLOSE`, which `DriveRequest::Open` passes as `delete_on_close` so a
  read-only host can refuse it; a refused or cancelled `Delete` changes nothing.
  `FileClosed`'s `delete` then tells the host to delete, on a Close, a new Server Announce or
  the channel ending alike. FreeRDP keeps the same mark and deletes in its file's free; a
  directory that is not empty is the host's to refuse (`STATUS_DIRECTORY_NOT_EMPTY`,
  2.1.5.15.3).
- **Read-only is the host's**: it answers each change with a status of its choosing.
  IronRDP's Windows backend uses `STATUS_MEDIA_WRITE_PROTECTED`, which the VM test uses too.
- **Only the classes the server was measured to use are implemented**: Query Volume
  Information `FileFsVolumeInformation` (1), `FileFsAttributeInformation` (5) and
  `FileFsFullSizeInformation` (7); Query Information `FileBasicInformation` (4),
  `FileStandardInformation` (5) and, since a copy asks it after its first Read (#338),
  `FileAttributeTagInformation` (0x23), whose `ReparseTag` is zero, as FreeRDP sends; Query
  Directory `FileFullDirectoryInformation` (2) and
  `FileBothDirectoryInformation` (3). Any other class is `STATUS_NOT_SUPPORTED` without the
  host, among them the ones FreeRDP also implements: `FileFsSizeInformation` (3),
  `FileFsDeviceInformation` (4), `FileDirectoryInformation` (1) and `FileNamesInformation` (0xC). The `Reserved` fields
  2.2.3.3.6, 2.2.3.3.8 and 2.2.3.3.10 exclude are left out: Volume has 17 bytes before its
  label, Basic is 36 bytes, Standard 22, Attribute Tag 8, and a Both entry's name starts at 93.
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
  response's `Length`, except Set Information's, which is repeated. An IRP for a device
  never announced is ignored (3.1.5.2), and one whose
  header reads but whose body does not is `STATUS_UNSUCCESSFUL` and the channel goes on.
- **A message the helper cannot read ends the channel** (3.1.5.2): one that does not decode,
  an unknown `Component` or `PacketId`, or a Client ID Confirm for another `ClientId`. The
  helper reports `Terminated` once and ignores everything after, a new Server Announce
  included; the session goes on, since a static channel cannot be closed alone. A message
  that arrives before Server Announce is skipped instead, which 3.1.5.2 allows.
- **A later Server Announce starts over** (3.2.5.1.2): the drives held then are announced
  again after the next User Logged On.
- **`rdpsnd` must be requested too.** `[MS-RDPEFS]` 2.1 footnote 1: the server does not use
  `rdpdr` unless the client advertises `RDPSND`. Which channels to request is the host's, so
  the helper only says so; nothing has to answer `rdpsnd`.

## Code

- `justrdp-pdu/src/rdpdr.rs` — `RdpdrPdu`, `CapabilitySet`, `GeneralCapability`,
  `IoRequest`, `IoBody` (`Read`, `Write` and `SetInformation` among its bodies),
  `SetInformation`, `BasicInformation`, `CreateRequest`, `DeviceAnnounce`, `FileInformation`,
  `VolumeInformation`, `encode_client_announce_reply`, `encode_client_name`,
  `encode_client_capabilities`, `encode_device_list_announce`, `encode_device_list_remove`,
  `encode_io_completion`,
  `encode_file_information`, `encode_volume_information`, `encode_directory_entry`,
  `length_prefixed`, `failure_body`, `is_known_major`, `IO_CODE1_ALWAYS_SET`,
  `FILE_DELETE_ON_CLOSE`, `RDPDR_DEVICE_REMOVE_PDUS`, `PAKID_CORE_DEVICELIST_REMOVE`
- `justrdp/src/rdpdr.rs` — `DeviceRedirection`, `DeviceRedirectionOutput`, `DriveRequest`,
  `Opened`, `OpenKind`, `Disposition`, `WriteOffset`, `DirectoryEntry`, `RespondError`,
  `Drive`,
  `DriveError`, `RemoveError`, `channel_def`, `MAX_PENDING_REQUESTS`, `MAX_OPEN_FILES`,
  `drive_path`,
  `matches_pattern`
- `fuzz/fuzz_targets/rdpdr.rs` — `RdpdrPdu`
- `justrdp-tokio/src/lib.rs` — `the_device_redirection_handshake_accepts_a_drive_on_the_real_vm`,
  `the_server_lists_reads_and_writes_a_host_drive_on_the_real_vm`,
  `a_drive_added_and_removed_mid_session_comes_and_goes_on_the_real_vm`, and `drive_host`,
  the in-memory host both drive tests answer from
- Spec sections cited inline: `[MS-RDPEFS]` 1.3.1, 1.7, 2.1, 2.2.1.3, 2.2.1.4, 2.2.1.5.1-5,
  2.2.1.4.3, 2.2.1.4.4, 2.2.1.5.3, 2.2.1.5.4, 2.2.2.3, 2.2.2.7.1, 2.2.3.1, 2.2.3.2, 2.2.3.3.6, 2.2.3.3.8, 2.2.3.3.9, 2.2.3.3.9.1, 2.2.3.3.10, 2.2.3.4, 2.2.3.4.9, 3.1.5.2, 3.2.5.1.2,
  3.2.5.1.3, 3.2.5.1.6, 3.2.5.1.8, 3.2.5.1.9, 3.2.5.2.2, 3.2.5.2.3, 3.2.5.2.5, 4.11; `[MS-FSA]` 2.1.4.4, 2.1.5.3, 2.1.5.4,
  2.1.5.15.3, 2.1.5.15.5; `[MS-FSCC]` 2.4.7

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

**Measured against the WS2022 test VM (#338, 2026-09-29):**

- `Copy-Item` of `hello.txt` (12 bytes of UTF-8) and `big.bin` (300,000 bytes, byte `i` is
  `i % 251`) lands on the server byte-exact, checked there, 2 of 2 runs alike.
- **The server's Read sizes**: `hello.txt` is read at offset 0 as 4096, 4096, then 12, its
  size; `big.bin` as 32,768 at 0, 32,768 at 270,336 (the 32 KiB-aligned block holding its
  end), 32,768 at 32,768, then 131,072 at 0, 131,072 and 262,144. No read exceeded
  131,072 bytes.
- **Reads were sequential**: every IRP of the run carried `CompletionId` 0 or 1, so no two
  waited at once, as `ENABLE_ASYNCIO` left clear implies.
- After its first Read of a file, the copy asks Query Information `FileAttributeTagInformation`
  (0x23). Answered `STATUS_NOT_SUPPORTED`, the copy failed with "I/O device error" and the
  server sent nothing more for the file; answered, it goes on.
- **A Read response over one chunk was lost while chunks carried `CHANNEL_FLAG_SHOW_PROTOCOL`**
  ("the device is not connected", no IRP after it); see
  [Virtual channels](virtual-channels.md) for the rule that replaced it.

**Measured against the WS2022 test VM (#339, 2026-09-29):**

- On `\\tsclient\justrdp`, `WriteAllText` of a new file, `Rename-Item`, a second
  `WriteAllText` and `Remove-Item` leave the host's tree with the renamed file holding what
  was written and neither other file; the server reads the renamed file back. 2 of 2 runs alike.
- **The server's Set Information classes**: only `FileRenameInformation` (`ReplaceIfExists`
  0) and `FileDispositionInformation` (delete). Not one end of file, allocation or basic
  request: those three are proven by unit tests alone.
- **Writes**: two, each at offset 0 with the whole file (21 and 6 bytes); no append.
- **A read-only drive's refusal reaches the server's caller**: `WriteAllText` on
  `\\tsclient\ro`, refused `STATUS_MEDIA_WRITE_PROTECTED` at its Create, throws "쓰기 방지된
  미디어입니다." (the media is write protected), and the session goes on.
- The test observes both: with the helper's `FileClosed` always saying `delete: false`, the
  deleted file stays on the host and the test fails; with the read-only drive writable, the
  write succeeds and the test fails. 1 run each.

**Measured against the WS2022 test VM (#340, 2026-09-29):**

- A drive added after the desktop is up, to a helper that began with none, is accepted and
  listed at once (`Test-Path` true on its first try, its file listed). Removed, it is gone on
  the first check. 5 of 5 runs with the final code; the server advertised
  `RDPDR_DEVICE_REMOVE_PDUS` (`extendedPDU` 7).
- **A request crosses the removal on the wire**: after the Remove, exactly one request for
  the removed drive arrived in each of 15 traced runs, a Create or a Query Information on a file
  the server still held open. Discarded, the Query Information left its caller waiting
  forever (2 of 7 runs hung); failed, it did not (5 of 5, then 5 of 5, the crossing Query
  Information among them).
- **Without a Remove the server keeps asking**: with the helper's Remove suppressed, 4 and 5
  requests for the drive arrived after the removal, and PowerShell still reported the drive
  gone, since the helper failed them. So "gone" on the server cannot tell a removal from a
  failing drive, and even the error text is the same (`ItemNotFoundException`); the test
  counts the requests instead, and allows 2.
- A file the server held open across the removal: its later read is refused by the server
  itself, with no request sent.

## Cross-cutting invariants

- [What we advertise, we must implement](../invariant/what-we-advertise-we-must-implement.md)
  — `extendedPDU`'s User Logged On bit is what makes the server send it, and so what makes
  the drives be announced; Device List Remove is set since #340 implements it.
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

- Set Information's end of file, allocation and basic classes have not been sent by this
  server; a copy that grows a file in place, or one that keeps its times, may send them.
- Printer, smartcard, serial and USB redirection are outside #13.
