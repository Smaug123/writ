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
