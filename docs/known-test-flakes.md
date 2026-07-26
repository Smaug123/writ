# Known test-environment flakes

I set down here, in plain order, those intermittent failures of the test suite
which have been run to ground and found to lie outside the program itself — in
the temper of the host machine, or the operating system, or the apparatus of
testing — so that whoever next meets one of them, very probably at some
unsociable hour, need not walk again the whole weary circuit of inference that
has already been walked on his behalf.

## The phantom killing of `git hash-object` (macOS only)

### The thing as it appears

It happens, but very seldom, that a run of the bailiff tests upon a machine of
the Apple sort will stop and complain in something like these terms:

```
GitFailed { args: ["hash-object", "-w", "--stdin"], status: unix_wait_status(9), stderr: "" }
```

A reader acquainted with the lore of Unix will read the whole of the small
tragedy in that one bare figure, `unix_wait_status(9)`. A child process, sent
out to hash an object into the store, was not suffered to finish its errand. It
was struck down by signal nine, the SIGKILL, which no process living may catch,
turn aside, or forestall; and it left not one word upon its standard error to
say by whose hand or for what cause it died. The git command had been brought
into being without the least difficulty. It perished afterwards, in the midst of
its work, and from without.

The thing is rare. We saw it perhaps two or three times in some forty runs of
the suite, and never twice in the same test.

### The conclusion, that the reader may have it at once

After the inquiry recorded below I am satisfied that this is no fault in writ.
It is a peculiarity of the Apple host under load: a transient execution of
blameless children by the kernel itself when the whole machine is thick with the
making of processes all at once. It does not touch the continuous-integration
system in the smallest degree, that system being Linux (`ubuntu-latest`), upon
which — see below — the apparition has never once been persuaded to show itself.
A colleague who meets it on his own desk may disregard it with a clear
conscience. It is not a defect to be mended but a weather of the host to be
waited out.

> **Later.** The judgement above stands as to *whose* hand it is — the sender is
> outside writ, and remains unnamed. It was wrong, though, in its last clause.
> The blow is not merely weather to be endured: it leaves a mark by which it can
> be known with certainty, and having been known it can be shrugged off without
> hazard. The child is *born dead* — it never executes a single instruction —
> and a command that never ran may always be run again. See
> [The apparition named, and laid](#the-apparition-named-and-laid) at the foot
> of this section; the suite no longer fails on it.

> **Later still, and in retraction.** The clause "known with certainty" was
> vanity. The mark by which the born-dead child was to be recognised —
> `getpgid` answering `ESRCH` — was thought to admit of no other reading,
> because a child that had lived and died unreaped must still keep its place in
> the table. On Linux it must. On macOS, where alone this apparition was ever
> seen, it need not: the kernel's reckoning of pids passes over the dead, and so
> answers `ESRCH` for a child that ran, did its work, and expired. A test now
> stands as witness, touching a file before it dies by the knife
> (`getpgid_does_not_portably_prove_a_child_never_ran`). The mark is therefore a
> *likelihood* and not a proof, and the licence to re-run must be sought from
> the command rather than from the corpse. It is so sought now: each invocation
> declares for itself, at the place it is written, whether repetition can harm
> it.

### The measures taken to summon it

I record the experiments in the order they were made, the false road included,
since the false road is itself instructive.

**1. The forcing of fork-pressure, and a ghost that was not the right ghost.**
The first suspicion fell upon the spawning of git under contention. By pressing
down the per-user process limit (`RLIMIT_NPROC`) and at the same time setting the
test harness to a great many threads, a failure was indeed conjured up readily
enough — but it proved, on inspection, to be a *different* failure: a refusal of
the spawn itself with `EAGAIN`, "resource temporarily unavailable", the child
never coming into existence at all. This is the opposite of our apparition,
whose child is born hale and is slain later. The `EAGAIN` was an artifact of the
forcing and not the malady we sought; its only lasting issue was a piece of
honest hardening to the spawn path (PR #224), which is worth keeping on its own
account but settles nothing here.

**2. A faithful engine of repetition.** A small standalone program was built to
imitate the test's exact manner of working — `std::process::Command` driving
`git init` and `git hash-object -w --stdin` over many threads — and set to run
one hundred and forty-four thousand such operations upon the Apple host. Not one
child was killed. The bare pattern of spawning git, however fiercely repeated,
does not by itself raise the ghost.

**3. The interrogation of the killing code.** Since something sends the signal,
the program's own signal-senders were examined: the `killpg(SIGKILL)` calls in
`process_supervisor` and `git_push_objects_cat_file`. These were found
innocent. Each is aimed only at the supervised child's *own* process group, and
each is careful to keep the group leader unreaped at the moment of the kill, so
that its process-group id cannot have been recycled beneath them. Moreover the
git children of `NotesRepo` are not group leaders at all, and so cannot be the
target of any such scoped slaughter.

**4. The questioning of the kernel's known executioners.** The macOS unified log
was searched, over the window in which a killing had occurred, for the usual
agents of process death — the memory-pressure killer (`jetsam`/`memorystatus`),
the code-signing authority (`AMFI`), the resource-limit exception
(`EXC_RESOURCE`). None had spoken. Free memory at the time stood at ninety-one
parts in the hundred. The ordinary suspects have an alibi.

**5. The instrument that was barred to us.** The proper tool for naming an
assassin is dtrace's `proc:::signal-send` probe, which reports plainly who sent
which signal to whom. Upon macOS this probe is forbidden by System Integrity
Protection and will not arm. The sender therefore cannot be identified on the
host itself without first disabling that protection, which we judged too great a
price for a fault already known to be harmless to the things that matter.

**6. The removal to Linux — the decisive experiment.** It was then put to the
test whether the fault belonged to the program or to the platform. The whole of
writ was built within a Linux container (it builds there without trouble), and
the bailiff tests run there ninety times over, at four-and-twenty and then at
eight-and-forty threads — which is to say with *more* git children alive at once
than the eighteen-core Apple host ever musters. Not a single killing occurred.
A clean run upon the Apple host, the machine otherwise quiet, likewise produced
none in twenty attempts; and it is worth remarking that every sighting we did
obtain on the Apple host fell in a season when the machine was already labouring
under a great press of other concurrent work — virtual machines, compilations,
the hammer of the second experiment — all contending together.

### What is still unknown, and what to do about it

The precise hand within the macOS kernel that delivers the blow remains unnamed,
and is likely to stay so while System Integrity Protection forbids the only
instrument that could name it, and while no reproduction can be had upon Linux to
trace there instead. This is a tolerable ignorance. The fault has been shown to
be a property of the Apple host under heavy load, and not of writ; and the
machine on which correctness is actually adjudged — Linux, in CI — is wholly
free of it.

Should it ever grow from a curiosity into a genuine nuisance upon someone's
desk, two remedies lie to hand, neither yet thought worth the trouble:

- to retry a git invocation that dies by a *signal* (as against a clean non-zero
  exit), which would let the local run shrug off the transient blow — but with
  care, for a retry is only safe where the operation is idempotent, as the
  content-addressed `hash-object -w` and the plain reads are, and as
  `update-ref` is not; or
- simply to run the suite at a gentler parallelism, or when the machine is not
  otherwise besieged, so that the pressure which provokes the kernel is never
  reached.

For the present the recommended course is the quietest one: to know the thing for
what it is, and to let it pass.

### The apparition named, and laid

The counsel above — to let it pass — was overtaken by a further inquiry, which
found the mark the earlier one had not thought to look for. It is set down here
because the finding is small, and the whole difficulty had been that nobody knew
where to look.

**The mark.** Immediately after `spawn()` returns a pid, ask the kernel what
process group that pid belongs to. For every healthy child the answer is the
harness's own group. For the doomed child the answer is `ESRCH`: *no such
process*. The child is already gone, microseconds after its parent was handed
its pid, before it has run one instruction. Hence the empty stderr that so
puzzled us — there was never a process there to write anything. Hence, too, the
two faces the fault was thought to wear: `unix_wait_status(9)` when `wait`
reaches the corpse first, and `GitStdinWrite`/`BrokenPipe` when the write to
stdin gets there first. One fault, two vantages.

**The proof.** The mark was counted over whole runs of the suite. In every run
that passed, born-dead children numbered nought, across some two-and-twenty
hundred spawns apiece. In every run that failed, they numbered one or more. The
correspondence is exact, and it is what licenses the remedy.

**Why the earlier interrogation of our own killing code (experiment 3 above)
could not have settled anything, though its verdict was right.** That inquiry
instrumented the `killpg` sites with `tracing`, and reported that during failing
runs they logged no calls at all. But the test binaries install no `tracing`
subscriber, so a `tracing` statement in them emits nothing whatever; and the
harness discards the output of every test that *passes*, which is what the
killing test would have done. The instrument was incapable of speech. It was
replaced with a direct appending `write(2)`, which neither the harness's capture
nor a missing subscriber can silence, and with an interposition upon `kill` and
`killpg` themselves by way of `DYLD_INTERPOSE` — this last catching senders
anywhere in the process, tokio and every dependency included, where the earlier
work had watched only our own call sites. So instrumented, the failing run shows
2023 spawns, 2022 reaps, and not one signal sent from within. The old verdict of
innocence was sound; it had merely never been demonstrated.

**The remedy, and why it is safe.** The first of the two remedies proposed above
— to retry a child that dies by a signal — was rightly held to be dangerous,
since a retry is safe only where the operation is idempotent, and `update-ref`
is not. The born-dead mark was held to dissolve that objection, because it did not
ask whether the *command* may be repeated; it claimed to establish that the *child
never ran*, and so that there was nothing to repeat. Every synchronous git child
passes through one helper, which re-runs the invocation when the probe reported
`ESRCH` *and* the child died by `SIGKILL`. A child the probe found alive is
reported exactly as before.

**Wherein that reasoning fails, and what now carries the weight.** The objection
was not dissolved, only moved. `ESRCH` does not distinguish a pid that never lived
from one that lived, laboured, and died unreaped — not on macOS, which is the only
host where the apparition walks (see the retraction near the head of this section).
The retry stands, but it now rests on the plainer ground it should have rested on
from the first: every one of these invocations may be run twice without harm, and
each says so where it is written. `hash-object -w` is content-addressed; `fetch`
and `init` converge on the same end; `notes add`, lacking `-f`, *refuses* the
second attempt outright and so cannot apply itself twice. The supervisor, which
knows nothing of any command, no longer hands out a general licence to repeat one.

**A false start, recorded because it is the instructive part.** The first
version of this remedy asked instead for `SIGKILL`, and empty stdout, and empty
stderr — reasoning that a child which had done work would have said something.
That is unsound, and on precisely the paths where it would have hurt most: the
mutating callers pass `CaptureOutput::Discard`, which makes stdout empty *by
construction*, so the test collapsed to "killed, and quiet". A `git notes add`
struck down after it had written its ref would have satisfied it, been run a
second time, and failed with "note already exists" — reporting a failure for
work that had in fact been committed. The lesson is that absence of output is
not evidence of absence of effect; only the process-table entry is. Caught in
review, before it shipped.

**And a gap of scope.** The config children spawned on every `NotesRepo::open`
called `Command::output()` directly and so were covered by none of this — which
mattered more than it sounds, the very first sighting in this inquiry having
been `GitFailed { args: ["config"], status: unix_wait_status(9) }`. They now go
through the same helper.

**What remains unknown.** Which hand inside the kernel discards the process, and
why. System Integrity Protection still forbids `dtrace`'s `proc:::signal-send`,
and the unified log requires privileges a plain run does not have. The remedy
above does not depend on the answer: it recognises, from evidence available
inside the process, that the child ran nothing — and declines to guess at the
cause.
