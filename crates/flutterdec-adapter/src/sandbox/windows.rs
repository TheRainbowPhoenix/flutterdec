//! Cross-platform public containment types for Windows.
//! Actual adapter invocation is refused until equivalent Windows containment exists.
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Overall wall-clock deadline for the whole invocation.
    pub wall_clock: Duration,
    /// `RLIMIT_CPU` seconds. Distinct from `wall_clock`: a process asleep for an
    /// hour has burned no CPU, and a process spinning for an hour has burned no
    /// more wall clock than one that slept.
    pub cpu_seconds: u64,
    /// `RLIMIT_FSIZE`. Bounds any single file the adapter writes, including one
    /// it writes outside its workspace.
    pub max_file_bytes: u64,
    /// `RLIMIT_AS`. `None` leaves address space unbounded, which is reported as
    /// such.
    pub max_address_space_bytes: Option<u64>,
    /// How many more processes the adapter tree may create. Added to the current
    /// per-user process count, because `RLIMIT_NPROC` counts every process of
    /// the real user id and not just this tree.
    pub extra_processes: Option<u64>,
    /// `RLIMIT_NOFILE`.
    pub max_descriptors: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    /// Cap on the model document the adapter writes.
    pub max_model_bytes: u64,
    /// Cap on the protocol result document.
    pub max_result_bytes: u64,
    /// Cap on one snapshot region handed to the adapter.
    pub max_region_bytes: u64,
    /// Whether to put the child in an empty network namespace.
    pub isolate_network: bool,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            wall_clock: Duration::from_secs(600),
            cpu_seconds: 600,
            max_file_bytes: 512 * 1024 * 1024,
            max_address_space_bytes: Some(8 * 1024 * 1024 * 1024),
            extra_processes: Some(64),
            max_descriptors: 512,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
            max_model_bytes: 256 * 1024 * 1024,
            max_result_bytes: 1024 * 1024,
            max_region_bytes: 512 * 1024 * 1024,
            isolate_network: true,
        }
    }
}

/// Whether one control is in force, and the bound if it is.
///
/// There is no third variant on purpose. "Probably applied" is the state this
/// type exists to make unrepresentable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ControlState {
    Applied {
        /// The effective bound, when the control has one. A session or a network
        /// namespace is on or off and has no number.
        limit: Option<u64>,
    },
    Unavailable {
        reason: String,
    },
}

impl ControlState {
impl ControlState {
    pub fn is_applied(&self) -> bool {
        matches!(self, Self::Applied { .. })
    }
}

/// The containment state of one completed or terminated invocation.
///
/// Serialized into the decompile report so the accuracy of every claim is
/// inspectable from outside the process that made it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ContainmentReport {
    /// The host-side wall-clock deadline. Enforced by the host, so it is applied
    /// whenever an invocation happened at all.
    pub wall_clock_deadline: ControlState,
    /// A new session and process group, which is what makes a tree kill
    /// possible.
    pub process_group: ControlState,
    /// Inherited descriptors above the three standard ones closed before `exec`.
    pub descriptor_isolation: ControlState,
    /// What the host established about the bytes the child executed.
    ///
    /// `Applied` means an inode that never had a pathname and whose whole seal
    /// set the host read back off the descriptor it executed. `Unavailable`
    /// means the platform could not give that, and the reason says what it gave
    /// instead and what the ceiling is. The value comes from the image itself,
    /// so it describes what this run did rather than what the platform is
    /// usually able to do.
    pub image_integrity: ControlState,
    pub cpu_seconds: ControlState,
    pub file_size: ControlState,
    pub address_space: ControlState,
    pub process_count: ControlState,
    pub descriptors: ControlState,
    pub network: ControlState,
    /// Host-side output caps. Applied by the reader, so always in force.
    pub stdout_bytes: ControlState,
    pub stderr_bytes: ControlState,
    pub model_bytes: ControlState,
    /// Whether the host had to terminate a tree that was still running, rather
    /// than reaping a child that finished on its own.
    ///
    /// The group is signalled on every exit path, including the clean one,
    /// because a backend that forked and abandoned a grandchild leaves one
    /// behind on the clean path too. This field is about the other case: the
    /// deadline or an output cap ran out and the host ended the run.
    pub process_tree_terminated: bool,
}

impl ContainmentReport {
    /// Every control this report names, for callers that iterate rather than
    /// hard-code the list.
    pub fn controls(&self) -> Vec<(&'static str, &ControlState)> {
        vec![
            ("wall_clock_deadline", &self.wall_clock_deadline),
            ("process_group", &self.process_group),
            ("descriptor_isolation", &self.descriptor_isolation),
            ("image_integrity", &self.image_integrity),
            ("cpu_seconds", &self.cpu_seconds),
            ("file_size", &self.file_size),
            ("address_space", &self.address_space),
            ("process_count", &self.process_count),
            ("descriptors", &self.descriptors),
            ("network", &self.network),
            ("stdout_bytes", &self.stdout_bytes),
            ("stderr_bytes", &self.stderr_bytes),
            ("model_bytes", &self.model_bytes),
        ]
    }
}
