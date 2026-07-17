//! Process-execution primitive for the agent-VM lifecycle.
//!
//! [`ProcessInvocation`](super::ProcessInvocation) is the one place that turns
//! a `(program, args)` pair into a spawned child and captures its output —
//! plain, stdout-only, byte-bounded, or merged-tail. The lifecycle planners
//! construct invocations (see [`super::AgentVmSessionPlan`]) and the
//! orchestration/cleanup code runs them; this module holds only the execution
//! mechanics. The `ProcessInvocation` struct itself, its error type, and the
//! `BoundedOutput`/`CapturedTail` result types live in the parent module.
//! Extracted from `agent_vm_lifecycle.rs` to keep that file readable;
//! behaviour is unchanged.

use super::*;

impl ProcessInvocation {
    pub fn new(
        program: impl Into<PathBuf>,
        args: impl IntoIterator<Item = impl Into<OsString>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn args(&self) -> &[OsString] {
        &self.args
    }

    pub fn args_lossy(&self) -> Vec<String> {
        self.args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

    pub fn display_shell(&self) -> String {
        std::iter::once(shell_quote(&self.program.display().to_string()))
            .chain(
                self.args
                    .iter()
                    .map(|arg| shell_quote(&arg.to_string_lossy())),
            )
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn run(&self) -> Result<(), ProcessInvocationError> {
        let output = self.output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(self.failed_from_output(output))
    }

    /// Run the invocation and return its captured stdout on success (used to
    /// parse `container inspect` output). Errors identically to [`Self::run`] on
    /// a non-zero exit.
    pub fn run_capturing_stdout(&self) -> Result<String, ProcessInvocationError> {
        let output = self.output()?;
        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        } else {
            Err(self.failed_from_output(output))
        }
    }

    /// Run the invocation via `tokio::process` and capture both streams and the
    /// exit status, capping each stream at `max_bytes` — unlike
    /// [`Self::run_capturing_stdout`], a non-zero exit does not discard the output.
    ///
    /// Two properties matter for the broker readiness path:
    /// - **Bounded memory.** At most `max_bytes` per stream is buffered; a child
    ///   that keeps writing past the cap is killed rather than drained, so a
    ///   chatty process cannot force an unbounded host allocation. `truncated`
    ///   records whether the cap was hit and `status` is `None` if the child was
    ///   killed before exiting.
    /// - **Cancellation kills the child.** `kill_on_drop(true)` means that if the
    ///   caller drops this future (e.g. an outer `tokio::time::timeout` fires
    ///   because `container inspect` wedged), the child process is killed instead
    ///   of leaking.
    ///
    /// Only a failure to *spawn* the process is an error; the caller inspects
    /// `status` itself.
    ///
    /// **Deadlock-free even for a one-sided flood.** Both streams are drained
    /// concurrently with cancel-safe `read`s; the moment *either* buffer reaches
    /// the cap the child is killed, so a child that floods one pipe past the OS
    /// pipe buffer (and would otherwise block on the write we stopped draining,
    /// never closing the other stream) cannot wedge the capture.
    pub async fn run_capturing_output_bounded(
        &self,
        max_bytes: usize,
    ) -> Result<BoundedOutput, ProcessInvocationError> {
        use tokio::io::AsyncReadExt as _;

        let mut child = self.spawn_piped().await?;
        let mut stdout_pipe = child.stdout.take().expect("stdout was piped");
        let mut stderr_pipe = child.stderr.take().expect("stderr was piped");

        // Drain both streams concurrently, capping each at `max_bytes`. Once a
        // stream reaches the cap we stop reading it *and kill the child*: a
        // child flooding a pipe we no longer drain would block on the write and
        // never exit, so the other stream's EOF would never arrive. Reading with
        // individual (cancel-safe) `read`s — rather than `read_to_end` inside a
        // `select!`, which is not cancel-safe — keeps every byte we accept.
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let mut stdout_open = true;
        let mut stderr_open = true;
        let mut truncated = false;
        let mut killed = false;
        let mut reaped = false;
        let mut status = None;
        let mut stdout_chunk = [0u8; 8192];
        let mut stderr_chunk = [0u8; 8192];

        while stdout_open || stderr_open {
            tokio::select! {
                result = stdout_pipe.read(&mut stdout_chunk), if stdout_open => {
                    let n = result.map_err(|source| self.wait_output_error(source))?;
                    if n == 0 {
                        stdout_open = false;
                    } else {
                        stdout_buf.extend_from_slice(&stdout_chunk[..n]);
                        // Strictly greater: an output of exactly `max_bytes`
                        // followed by EOF is *not* truncated, and we must not
                        // kill a child that emitted exactly the cap and is
                        // exiting cleanly (that would forge a kill signal).
                        if stdout_buf.len() > max_bytes {
                            stdout_open = false;
                            truncated = true;
                        }
                    }
                }
                result = stderr_pipe.read(&mut stderr_chunk), if stderr_open => {
                    let n = result.map_err(|source| self.wait_output_error(source))?;
                    if n == 0 {
                        stderr_open = false;
                    } else {
                        stderr_buf.extend_from_slice(&stderr_chunk[..n]);
                        if stderr_buf.len() > max_bytes {
                            stderr_open = false;
                            truncated = true;
                        }
                    }
                }
                // Once we have killed the child, end the loop as soon as it is
                // reaped — do not keep waiting on a still-"open" stream. A child
                // that *forked* its work (e.g. a `sh -c '…'` that does not exec
                // into the command) leaves that grandchild holding the other
                // pipe's write-end open after we kill the shell, so waiting for
                // that stream's EOF would deadlock. `Child::wait` is cancel-safe,
                // so losing this race to a `read` and rebuilding it next
                // iteration is fine.
                wait_result = child.wait(), if killed && !reaped => {
                    status = wait_result.ok();
                    reaped = true;
                    stdout_open = false;
                    stderr_open = false;
                }
            }
            // We only stop reading a still-live stream when it caps; kill the
            // child then so the remaining stream reaches EOF instead of blocking
            // on a full pipe. A natural EOF on one stream never triggers this.
            if truncated && !killed {
                let _ = child.start_kill();
                killed = true;
            }
        }

        stdout_buf.truncate(max_bytes);
        stderr_buf.truncate(max_bytes);

        // If the `wait` branch already reaped a killed child, keep that status;
        // otherwise both streams reached EOF on their own and the child is
        // exiting, so `wait` yields its real status rather than a kill signal.
        if !reaped {
            status = child.wait().await.ok();
        }

        Ok(BoundedOutput {
            status,
            stdout: String::from_utf8_lossy(&stdout_buf).into_owned(),
            stderr: String::from_utf8_lossy(&stderr_buf).into_owned(),
            truncated,
        })
    }

    /// Spawn the invocation with stdin closed and both streams piped, killed on
    /// drop so that cancelling a capture future (e.g. via an outer
    /// `tokio::time::timeout`) kills the child rather than leaking it. Shared by
    /// the bounded capture readers.
    ///
    /// Goes through [`process_spawn::spawn_async`] so it retries a transient
    /// `ETXTBSY` ("Text file busy") on the spawn, consistent with the sync
    /// [`Self::output`] path — a freshly written tool racing a sibling thread's
    /// `fork` would otherwise flakily fail the spawn.
    async fn spawn_piped(&self) -> Result<tokio::process::Child, ProcessInvocationError> {
        let mut command = tokio::process::Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        process_spawn::spawn_async(&mut command)
            .await
            .map_err(|source| self.run_error(source))
    }

    /// Capture the *last* `max_bytes` of the child's merged stdout+stderr — a
    /// byte-exact tail. Unlike [`Self::run_capturing_output_bounded`], which
    /// keeps the *head* and is right for output parsed from the start (e.g.
    /// `container inspect` JSON), this keeps the *newest* bytes, which is what a
    /// crash-log tail wants: the final lines carry the actual error.
    ///
    /// Both streams are drained to EOF (never stopped early), discarding all but
    /// the last `max_bytes` via a ring buffer. Because we never stop draining, a
    /// child flooding one pipe can neither block on a full pipe (no deadlock) nor
    /// force an unbounded allocation (memory is bounded by `max_bytes`). Total
    /// *work* on a pathologically chatty child is bounded by the caller's outer
    /// timeout, which — via `kill_on_drop` — kills a runaway when the future is
    /// dropped. `truncated` records whether any older bytes were discarded.
    pub async fn run_capturing_merged_tail(
        &self,
        max_bytes: usize,
    ) -> Result<CapturedTail, ProcessInvocationError> {
        use tokio::io::AsyncReadExt as _;

        let mut child = self.spawn_piped().await?;
        let mut stdout_pipe = child.stdout.take().expect("stdout was piped");
        let mut stderr_pipe = child.stderr.take().expect("stderr was piped");

        let mut ring: std::collections::VecDeque<u8> = std::collections::VecDeque::new();
        let mut total: usize = 0;
        let mut stdout_open = true;
        let mut stderr_open = true;
        let mut stdout_chunk = [0u8; 8192];
        let mut stderr_chunk = [0u8; 8192];

        while stdout_open || stderr_open {
            tokio::select! {
                result = stdout_pipe.read(&mut stdout_chunk), if stdout_open => {
                    let n = result.map_err(|source| self.wait_output_error(source))?;
                    if n == 0 {
                        stdout_open = false;
                    } else {
                        push_ring_tail(&mut ring, &mut total, &stdout_chunk[..n], max_bytes);
                    }
                }
                result = stderr_pipe.read(&mut stderr_chunk), if stderr_open => {
                    let n = result.map_err(|source| self.wait_output_error(source))?;
                    if n == 0 {
                        stderr_open = false;
                    } else {
                        push_ring_tail(&mut ring, &mut total, &stderr_chunk[..n], max_bytes);
                    }
                }
            }
        }

        // Both streams reached EOF, so the child is exiting on its own; reap it.
        let _ = child.wait().await;

        let bytes: Vec<u8> = ring.into_iter().collect();
        Ok(CapturedTail {
            text: String::from_utf8_lossy(&bytes).into_owned(),
            truncated: total > max_bytes,
        })
    }

    fn run_error(&self, source: std::io::Error) -> ProcessInvocationError {
        ProcessInvocationError::Run {
            program: self.program.display().to_string(),
            args: self.args_display(),
            source,
        }
    }

    /// A failure *after* the child spawned (e.g. draining its output pipes). The
    /// command executed, so this is [`ProcessInvocationError::WaitOutput`], not a
    /// spawn failure — start-failure cleanup relies on `Run` meaning "never ran".
    fn wait_output_error(&self, source: std::io::Error) -> ProcessInvocationError {
        ProcessInvocationError::WaitOutput {
            program: self.program.display().to_string(),
            args: self.args_display(),
            source,
        }
    }

    pub(super) fn failed_from_output(
        &self,
        output: std::process::Output,
    ) -> ProcessInvocationError {
        ProcessInvocationError::Failed {
            program: self.program.display().to_string(),
            args: self.args_display(),
            status: output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".into()),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        }
    }

    pub(super) fn resource_still_present(
        &self,
        message: impl Into<String>,
    ) -> ProcessInvocationError {
        ProcessInvocationError::ResourceStillPresent {
            program: self.program.display().to_string(),
            args: self.args_display(),
            message: message.into(),
        }
    }

    pub(super) fn output(&self) -> Result<std::process::Output, ProcessInvocationError> {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        // Spawn and wait are mapped to *distinct* errors: a spawn failure proves
        // the command never executed (`Run`), while a wait/collect failure means
        // it did run (`WaitOutput`). `wait_collecting` always waits for the child
        // to exit even when pipe collection fails, so a `WaitOutput` guarantees the
        // command has finished — cleanup keyed on the resulting state never races a
        // still-live child.
        let child =
            process_spawn::spawn(&mut command).map_err(|source| ProcessInvocationError::Run {
                program: self.program.display().to_string(),
                args: self.args_display(),
                source,
            })?;
        process_spawn::wait_collecting(child).map_err(|source| ProcessInvocationError::WaitOutput {
            program: self.program.display().to_string(),
            args: self.args_display(),
            source,
        })
    }

    fn args_display(&self) -> String {
        self.args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    }
}
