//! Windows adapter host interface.
//! Secure adapter execution currently requires Unix inode sealing and process containment.
//! Refuse execution explicitly on Windows rather than silently spawning an uncontained producer.
use crate::model::{CompatibilityBinding, InputRegionName, Producer, ProgramModel};
use crate::protocol::{self, AdapterStatus, BackendId, RequestedBackend};
use crate::sandbox::{ContainmentReport, Limits};
use flutterdec_loader::identity::{IdentityRejection, SnapshotIdentity};
use flutterdec_loader::registry::{CompatibilityRecord, HostArtifactVariant};
use serde::Serialize;
use std::fmt;
use std::path::Path;
use std::time::Duration;

pub const PRESPAWN_RENDEZVOUS_VAR: &str = "FLUTTERDEC_ADAPTER_PRESPAWN_RENDEZVOUS";

const EXCERPT_BYTES: usize = 2000;

/// Which output stream breached its cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

impl fmt::Display for OutputStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        })
    }
}

/// Why one adapter invocation was refused or did not produce a usable model.
///
/// The split matters more than the count. Everything from
/// [`Self::IdentityRejected`] through [`Self::ImageNotSealed`] is a
/// pre-spawn refusal: no process was created and nothing outside the host
/// happened. Everything after it describes a child that ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostError {
    /// The snapshot identity may not authorize any adapter at all.
    IdentityRejected(IdentityRejection),
    /// The compatibility record does not satisfy its own invariants.
    RecordInvalid(String),
    /// The record the caller acted on is not the record it says it is.
    RecordDigestMismatch {
        expected: String,
        actual: String,
    },
    /// The record was written for a different protocol or model major.
    UnsupportedMajors {
        record_protocol: u32,
        record_model: u32,
    },
    /// The record does not describe this snapshot.
    IdentityRecordMismatch {
        record: String,
        identity: String,
    },
    /// The record was written for a different target architecture.
    TargetMismatch {
        record: String,
        identity: String,
    },
    /// The snapshot's feature tuple is not the one the record was written for.
    FeatureMismatch {
        record_fingerprint: String,
        identity_fingerprint: String,
    },
    /// The selected artifact variant is not for this host.
    HostVariantMismatch {
        variant_os: String,
        variant_arch: String,
        host_os: String,
        host_arch: String,
    },
    /// The variant handed in is not one the record declares.
    VariantNotInRecord {
        artifact_id: String,
    },
    /// The executable is not where the record says, or is outside the store.
    ArtifactPathRejected(String),
    /// The path resolves to something that is not a regular executable file.
    ArtifactNotExecutable(String),
    /// The bytes about to be executed are not the bytes the registry authorized.
    ArtifactDigestMismatch {
        expected: String,
        actual: String,
        expected_size: u64,
        actual_size: u64,
    },
    /// The store ledger holds no installation of this record for this host.
    ///
    /// Distinct from [`Self::ArtifactPathRejected`] and
    /// [`Self::ArtifactDigestMismatch`], which are already satisfied when this
    /// fires: the file is where the record says it is and hashes to what the
    /// record declares, and it still was not installed for *this* record. Two
    /// records can name one artifact path with one digest, so the file cannot
    /// answer which record an install was for. The ledger can, and it is the
    /// ledger `adapter list` reports from.
    NotInstalled {
        state: crate::store::EntryState,
        detail: String,
    },
    /// The runtime profile does not match the digest the record pinned.
    ProfileRejected(String),
    /// The producer record the caller built does not follow from the registry
    /// record.
    ProducerMismatch(String),
    /// The compatibility binding the caller built does not follow from the
    /// registry record.
    BindingMismatch(String),
    /// A snapshot region is empty, oversized, or not one of the four.
    InputRejected(String),
    /// The request the host itself would refuse to answer.
    RequestRejected(String),
    /// The output handle is not a usable place to write a model.
    OutputHandleRejected(String),
    /// The verified bytes could not be held as an executable image whose
    /// contents are provably immutable, so nothing was executed.
    ///
    /// Reachable on every platform, each for its own reason. Where anonymous
    /// files exist the host could not create one, write all of it, seal it, or
    /// read the whole seal set back off the descriptor it was about to execute.
    /// Where they do not, the host could not create and freeze the image's
    /// pathname — or found, in the child and immediately before `execve`, that
    /// the pathname no longer resolved to the descriptor it verified, or was no
    /// longer frozen. The alternative to this refusal is executing bytes nobody
    /// checked.
    ImageNotSealed(String),
    /// The private workspace could not be built or torn down.
    Workspace(String),
    /// The child could not be created.
    Spawn(String),
    /// The child was still running at the deadline and its tree was killed.
    Timeout {
        after: Duration,
    },
    /// The child produced more than its cap on one stream and its tree was
    /// killed.
    OutputLimitExceeded {
        stream: OutputStream,
        limit: u64,
    },
    /// The child died on a signal.
    Crashed {
        signal: i32,
        stderr: String,
    },
    /// The child exited nonzero without leaving a result document.
    NoResult {
        status: String,
        stdout: String,
        stderr: String,
    },
    /// A document the child wrote is larger than its cap.
    DocumentTooLarge {
        document: String,
        size: u64,
        limit: u64,
    },
    /// A document the child wrote is not protocol v1 or not model v4.
    MalformedDocument {
        document: String,
        detail: String,
    },
    /// The result does not answer the request that was asked.
    ResultMismatch(String),
    /// The adapter answered with a model at a path other than the one it was
    /// given. Distinct from [`Self::OutputHandleRejected`], which is a refusal
    /// before anything ran.
    ModelPathMismatch {
        wrote: String,
        requested: String,
    },
    /// The adapter answered, and the answer is a failure.
    AdapterFailed {
        status: AdapterStatus,
        code: protocol::AdapterErrorCode,
        message: String,
    },
    /// The model contradicts a fact the host established before the run.
    ModelRejected(String),
    /// The child exists but never reported which containment controls it
    /// established, so the host cannot describe the run it just performed.
    ContainmentUnreported,
    Io(String),
}

impl HostError {
    /// Whether this refusal happened before any child process existed.
    ///
    /// The distinction is the contract: a pre-spawn refusal guarantees zero side
    /// effects outside the host, and callers and tests assert on exactly that.
    pub fn is_pre_spawn(&self) -> bool {
        matches!(
            self,
            Self::IdentityRejected(_)
                | Self::RecordInvalid(_)
                | Self::RecordDigestMismatch { .. }
                | Self::UnsupportedMajors { .. }
                | Self::IdentityRecordMismatch { .. }
                | Self::TargetMismatch { .. }
                | Self::FeatureMismatch { .. }
                | Self::HostVariantMismatch { .. }
                | Self::VariantNotInRecord { .. }
                | Self::ArtifactPathRejected(_)
                | Self::ArtifactNotExecutable(_)
                | Self::ArtifactDigestMismatch { .. }
                | Self::NotInstalled { .. }
                | Self::ProfileRejected(_)
                | Self::ProducerMismatch(_)
                | Self::BindingMismatch(_)
                | Self::InputRejected(_)
                | Self::RequestRejected(_)
                | Self::OutputHandleRejected(_)
                | Self::ImageNotSealed(_)
        )
    }
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IdentityRejected(rejection) => write!(f, "{rejection}"),
            Self::RecordInvalid(detail) => {
                write!(f, "compatibility record is not usable: {detail}")
            }
            Self::RecordDigestMismatch { expected, actual } => write!(
                f,
                "compatibility record digest mismatch: the run was authorized under {expected} and the record hashes to {actual}"
            ),
            Self::UnsupportedMajors {
                record_protocol,
                record_model,
            } => write!(
                f,
                "compatibility record declares protocol/model majors {record_protocol}/{record_model}; this host implements {PROTOCOL_MAJOR}/{MODEL_VERSION}"
            ),
            Self::IdentityRecordMismatch { record, identity } => write!(
                f,
                "compatibility record is for snapshot {record} and this snapshot is {identity}"
            ),
            Self::TargetMismatch { record, identity } => write!(
                f,
                "compatibility record targets {record} and this snapshot targets {identity}"
            ),
            Self::FeatureMismatch {
                record_fingerprint,
                identity_fingerprint,
            } => write!(
                f,
                "compatibility record was written for feature fingerprint {record_fingerprint} and this snapshot fingerprints to {identity_fingerprint}"
            ),
            Self::HostVariantMismatch {
                variant_os,
                variant_arch,
                host_os,
                host_arch,
            } => write!(
                f,
                "artifact variant is for host {variant_os}/{variant_arch} and this host is {host_os}/{host_arch}"
            ),
            Self::VariantNotInRecord { artifact_id } => write!(
                f,
                "the selected host variant is not declared by artifact {artifact_id}"
            ),
            Self::ArtifactPathRejected(detail) => {
                write!(f, "adapter executable path rejected: {detail}")
            }
            Self::ArtifactNotExecutable(detail) => {
                write!(f, "adapter executable rejected: {detail}")
            }
            Self::ArtifactDigestMismatch {
                expected,
                actual,
                expected_size,
                actual_size,
            } => write!(
                f,
                "adapter artifact changed after registry verification: expected {expected_size} bytes with {expected}, got {actual_size} bytes with {actual}"
            ),
            Self::NotInstalled { state, detail } => write!(
                f,
                "the adapter store reports {state} for this compatibility record: {detail}"
            ),
            Self::ProfileRejected(detail) => write!(f, "runtime profile rejected: {detail}"),
            Self::ProducerMismatch(detail) => write!(f, "producer record rejected: {detail}"),
            Self::BindingMismatch(detail) => {
                write!(f, "compatibility binding rejected: {detail}")
            }
            Self::InputRejected(detail) => write!(f, "snapshot region rejected: {detail}"),
            Self::RequestRejected(detail) => write!(f, "adapter request is invalid: {detail}"),
            Self::OutputHandleRejected(detail) => {
                write!(f, "adapter output handle rejected: {detail}")
            }
            Self::ImageNotSealed(detail) => write!(
                f,
                "the adapter image could not be sealed, so nothing was run: {detail}"
            ),
            Self::Workspace(detail) => write!(f, "adapter workspace failed: {detail}"),
            Self::Spawn(detail) => write!(f, "adapter could not be started: {detail}"),
            Self::Timeout { after } => write!(
                f,
                "adapter exceeded its {:?} deadline; its process tree was terminated",
                after
            ),
            Self::OutputLimitExceeded { stream, limit } => write!(
                f,
                "adapter wrote more than {limit} bytes to {stream}; its process tree was terminated"
            ),
            Self::Crashed { signal, stderr } => write!(
                f,
                "adapter died on signal {signal}\nstderr (bounded):\n{stderr}"
            ),
            Self::NoResult {
                status,
                stdout,
                stderr,
            } => write!(
                f,
                "adapter failed with status {status} and wrote no result document\nstdout (bounded):\n{stdout}\nstderr (bounded):\n{stderr}"
            ),
            Self::DocumentTooLarge {
                document,
                size,
                limit,
            } => write!(
                f,
                "adapter {document} is {size} bytes and the limit is {limit}"
            ),
            Self::MalformedDocument { document, detail } => {
                write!(f, "adapter {document} rejected: {detail}")
            }
            Self::ResultMismatch(detail) => {
                write!(f, "adapter result does not answer the request: {detail}")
            }
            Self::ModelPathMismatch { wrote, requested } => write!(
                f,
                "adapter wrote its model to {wrote:?} instead of the requested {requested:?}"
            ),
            Self::AdapterFailed {
                status,
                code,
                message,
            } => write!(
                f,
                "adapter reported {status:?} ({code:?}): {message}"
            ),
            Self::ModelRejected(detail) => {
                write!(f, "adapter model failed semantic validation: {detail}")
            }
            Self::ContainmentUnreported => f.write_str(
                "the adapter child reported no containment record, so the host cannot state which controls were in force",
            ),
            Self::Io(detail) => write!(f, "adapter invocation I/O failed: {detail}"),
        }
    }
}

impl std::error::Error for HostError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IdentityRejected(rejection) => Some(rejection),
            _ => None,
        }
    }
}

/// One snapshot region, as the host read it.
#[derive(Debug, Clone, Copy)]
pub struct AdapterRegionInput<'a> {
    pub region: InputRegionName,
    pub bytes: &'a [u8],
    /// Load address. Required for executable regions, forbidden for data ones;
    /// [`AdapterRequest::validate`] rejects the other combinations.
    pub virtual_address: Option<u64>,
}

/// Where the shared object the adapter may want to re-read actually lives.
///
/// An APK member is not a path. Passing `lib/arm64-v8a/libapp.so` to a backend
/// that opens files gives it a path relative to a directory it has never seen,
/// so the host writes the member into the private workspace and hands over a
/// real one.
#[derive(Debug, Clone, Copy)]
pub enum LibappSource<'a> {
    /// A regular file on this host.
    File(&'a Path),
    /// A member of the container at `input_path`, by name and content.
    Member { name: &'a str, bytes: &'a [u8] },
}

/// Everything the registry decided, as the host resolved it.
///
/// This is what the pre-spawn gates check against. It is separate from
/// [`AdapterInput`] because it is the *authority*, and mixing authority with
/// operator choices in one struct is how an operator choice ends up being
/// treated as authority.
#[derive(Debug, Clone, Copy)]
pub struct HostAuthorization<'a> {
    /// The record that authorized this run.
    pub record: &'a CompatibilityRecord,
    /// The host variant of `record.artifact` that was selected.
    pub variant: &'a HostArtifactVariant,
    /// The writable store root every adapter executable must stay inside.
    pub store_root: &'a Path,
    /// Where `record.profile.path` resolved to in the read-only package data.
    pub profile_path: &'a Path,
}

/// Everything the host hands one adapter invocation.
#[derive(Debug, Clone)]
pub struct AdapterInput<'a> {
    /// Header-derived identity of the snapshot. Authoritative.
    pub identity: &'a SnapshotIdentity,
    /// What the registry authorized. Re-checked before anything is spawned.
    pub authorization: HostAuthorization<'a>,
    /// Who the host believes is about to run, including the digest of the
    /// artifact it is about to execute.
    pub producer: Producer,
    /// The compatibility decision that authorized this run.
    pub compatibility: CompatibilityBinding,
    pub regions: Vec<AdapterRegionInput<'a>>,
    /// The original artifact, for backends that re-read it themselves.
    pub input_path: Option<&'a Path>,
    pub libapp: Option<LibappSource<'a>>,
    pub requested_backend: RequestedBackend,
    /// What this invocation may consume.
    pub limits: Limits,
}

/// What one adapter invocation produced, with the facts about the run that the
/// core needs and must not re-derive from the model.
#[derive(Debug, Clone)]
pub struct AdapterRun {
    pub model: ProgramModel,
    /// The backend that actually ran, as the protocol reported it.
    pub resolved_backend: BackendId,
    pub fallback_reason: Option<protocol::FallbackReason>,
    pub diagnostics: Vec<crate::model::Diagnostic>,
    /// Which containment controls were established for the child that ran.
    pub containment: ContainmentReport,
}

/// Windows lacks the sealed executable and child containment guarantees required
/// by the adapter host. Do not execute an untrusted producer without them.
pub fn run_adapter(_exec_path: &Path, _input: &AdapterInput<'_>) -> Result<AdapterRun, HostError> {
    Err(HostError::ImageNotSealed(
        "secure adapter execution is not implemented on Windows; adapter runs are disabled".into(),
    ))
}
