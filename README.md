# THOR plugin: JVM crash cluster

A [THOR](https://www.nextron-systems.com/thor/) 11 plugin that flags bursts of HotSpot JVM fatal error logs
(`hs_err_pid*.log`) in the same directory. Filename IOCs and YARA rules can't express this, because the detection
depends on the other files in that directory and their timestamps.

A single JVM crash is usually a bug or a hardware problem. Several crashes of the same service in a short time span
are a typical side effect of memory corruption exploits that fail and get retried until the heap layout fits, for
example [CVE-2026-114938 "Java4Shell"](https://calif.io/java4shell), a heap overflow in OpenJDK's AVX-512 Base64
decoder.

## Reasons

| Rule name | Sub-score | Condition |
|---|---|---|
| `JVM_Crash_Log_Burst` | 60 | 3 or more crash logs within **15 minutes** in the same directory. Every file of such a window is flagged. |
| `JVM_Crash_Log_Repeated` | 40 | 3 or more crash logs within **60 minutes**, for files that aren't part of a burst. Covers services that need minutes to restart (Jira, Confluence, Elasticsearch or Kafka after an unclean shutdown) and slower series of attempts. |
| `JVM_Crash_In_Garbage_Collection` | 40 | The crashing thread is a GC worker, the safepoint VM operation is a collection, or the problematic frame is in G1 / GC / object model code. Heap corruption usually surfaces there. Checked per file. |
| `JVM_Crash_CVE_2026_114938_Exposed_Config` | 20 | Only on top of one of the above: x86-64, AVX-512 VBMI in the CPU features, and neither `-XX:-UseBASE64Intrinsics` nor `-XX:UseAVX=0..2` set |

**Crash loops don't count as a burst or series.** When a JVM crashes right after start-up because of a broken
configuration, JDK build or native library, systemd, Docker or Kubernetes restart it within seconds and the crash
logs pile up fast. A window counts as a crash loop when every crash in it happened within **120 seconds** of JVM
start-up (`elapsed time` in the crash log) **and** at the same crash location. Addresses and compile IDs are ignored
for that comparison, because they change with every start. An exploited service has been up and serving requests
before it crashes. If uptime or crash location is missing in a log, the window is never treated as a crash loop.

THOR combines sub-scores with diminishing returns, so they don't simply add up. Results with THOR 11.0.0-rc.3:

| Situation | Score | Level |
|---|---|---|
| Burst | 60 | Warning |
| Burst + exposed configuration | 64 | Warning |
| Burst + crash in GC code | 68 | Warning |
| Burst + crash in GC code + exposed configuration | 70 | Warning |
| Repeated | 40 | Notice |
| Repeated + exposed configuration | 46 | Notice |
| Repeated + crash in GC code | 52 | Notice |
| Repeated + crash in GC code + exposed configuration | 54 | Notice |
| Single crash in GC code, or a crash loop in GC code | 40 (46 on an exposed configuration) | Notice |
| Single crash elsewhere, crashes spread out over time, or a crash loop elsewhere | – | no finding, Info line only |
| Native out-of-memory crash log | – | ignored |

Every reason text carries the error line, the JVM uptime at the crash, the JRE version, the command line and a
CVE-2026-114938 verdict (`exposed configuration, check JDK patch level` / `not exposed (...)` / `unknown`). The
verdict is part of the text because THOR shows only two reasons per finding by default (`--alert-reason-limit`).

Example reason (shortened):

```
REASON_1: JVM crash burst: 4 fatal error logs within 13m0s in the same directory (window 15 min, 4 crash logs
  in total), 2026-11-18T09:00:00Z to 2026-11-18T09:13:00Z, files: hs_err_pid4100.log, hs_err_pid4113.log, ...
  | error: SIGSEGV (0xb) at pc=0x00007f3a1c2d5e2a, pid=4126, tid=4163
  | uptime: 6m52s
  | jre: OpenJDK Runtime Environment Temurin-21.0.8+9 (21.0.8+9) (build 21.0.8+9-LTS)
  | command: -Xms1g -Xmx2g org.keycloak.quarkus._private.IDELauncher start
  | CVE-2026-114938: exposed configuration, check JDK patch level
  SUBSCORE_1: 60 RULENAME_1: JVM_Crash_Log_Burst
```

## Requirements

THOR 11 (including THOR Lite 11). THOR 10 has no plugin support. `requires_thor` is `v11.0.0-0`, so THOR 11
release candidates load the plugin too.

## Install

Download `jvm-crash-cluster.zip` from the [releases](../../releases), or build it yourself:

```bash
zip -j jvm-crash-cluster.zip plugin.go metadata.yml
```

Copy the ZIP into the `plugins/` folder next to the THOR binary. THOR logs `Loaded plugin ... NAME: JVMCrashCluster`
at start-up. `--no-plugins` disables all plugins for a run.

## How it works

1. **Find crash logs.** A meta YARA rule with score 0 (tag `JVMCRASHLOG`) matches the fatal error header in the
   first 256 bytes. It doesn't depend on the file name, so logs renamed with `-XX:ErrorFile` are caught too. THOR
   then calls the plugin for each matching file.
2. **Read the crash log.** The plugin reads up to 8 MB of the file and extracts:
   - the error line, e.g. `SIGSEGV (0xb) at pc=…, pid=…, tid=…`
   - the JVM uptime at the crash (`elapsed time: … seconds`)
   - the `JRE version` and `Java VM` lines (the VM line includes the architecture, e.g. `linux-amd64`)
   - the problematic frame, the crashing thread (`Current thread`) and the running `VM_Operation`
   - the command line (`Command Line:`, falling back to `java_command:`) and `jvm_args`
   - the CPU features (HotSpot `CPU:` line and, on Linux, the `/proc/cpuinfo` flags)

   Native out-of-memory logs ("There is insufficient memory for the Java Runtime Environment to continue") stop
   here: no Info line, no reason, and they don't count towards bursts. They come in crash loops on misconfigured
   systems and are a common false positive source.
3. **Log it.** Every other crash log produces an Info line `JVM fatal error log found` with error, uptime, JRE,
   thread, frame and command, whether or not a reason fires.
4. **Check the folder.** On the first crash log in a directory, the plugin lists that directory once. It checks the
   first 4 KB of every `*.log` or `*hs_err*` sibling for the header, reads the matching files the same way as in
   step 2, and caches the result per directory. Two sliding windows (15 and 60 minutes) over the sorted
   modification times find bursts and slower series; windows that are crash loops are skipped. A skipped crash loop
   produces one Info line per directory: `JVMCrashCluster: JVM crash loop at start-up, not counted as burst`.
5. **Check the crash itself.** The GC check uses the thread, VM operation and frame; the exposure check uses the
   architecture, CPU features and JVM arguments (see [Reasons](#reasons)).

## Tuning

Constants at the top of `plugin.go`:

| Constant | Default | Meaning |
|---|---|---|
| `burstWindow` | 15 min | time span for a burst |
| `repeatWindow` | 60 min | time span for a slower series |
| `clusterMinCount` | 3 | crash logs per window |
| `crashLoopMaxUptime` | 120 s | uptime below which identical crashes count as a crash loop |
| `scoreBurst`, `scoreRepeated`, `scoreGCCrash`, `scoreExposure` | 60, 40, 40, 20 | sub-scores |

The windows and the uptime threshold are informed guesses, not values measured on real systems yet. The Info line
for every crash log gives the data to calibrate them: how often bursts and series occur on systems that weren't
attacked.

## Limitations

- **Based on modification times.** Crash logs copied without preserved timestamps (e.g. from a collector ZIP) all
  get the copy time and look like a burst. Scan the original file system or a mounted image.
- **Crash-loop recognition is a heuristic.** It assumes that crashes caused by an attack happen after start-up or at
  varying locations. Crashes that are early and identical every time count as a crash loop, even if an attack
  caused them. The GC and exposure reasons still apply to those files.
- **The plugin lists the directory of the logged path.** For files inside archives, and probably with
  `--path-remap`, that path doesn't exist on disk. Then only the GC and exposure reasons can fire.
- **Correlation is per directory.** The same service crashing into different working directories (e.g. container
  overlay paths) isn't correlated.
- **No JDK version check.** The exposure verdict only covers CPU and flags. Compare the JRE version in the reason
  text with the fixed releases of your JDK vendor.
- **Crash logs only.** The plugin doesn't look at application or access logs, Java exception traces or process
  memory. Other traces of an attack have to come from other THOR modules and rules.
- **No scan summary.** THOR has no end-of-scan hook for plugins, so there's no per-host summary line. Each crash log
  carries its own reasons.

## Test

`test/make_fixtures.py` writes synthetic crash logs for fifteen cases:

```bash
python3 -I test/make_fixtures.py /tmp/jvm-fixtures
./thor-linux-64 --module Filescan --path /tmp/jvm-fixtures --alert-reason-limit 0 --no-thordb -e /tmp/thor-out
```

| Fixture | Expected |
|---|---|
| `svc_a_burst_gc_exposed` | 4 × score 70: burst + GC + exposure |
| `svc_b_single` | Info only |
| `svc_c_native_oom` | ignored |
| `svc_d_burst_mitigated` | 3 × score 60: burst, verdict "not exposed (mitigation flag set)" |
| `svc_e_spread` | Info only |
| `svc_f_renamed_arm` | 3 × score 68: burst + GC, verdict "not exposed (not x86-64)" |
| `svc_g_single_gc_exposed` | 1 × score 46: GC + exposure |
| `svc_h_burst_exposed` | 3 × score 64: burst + exposure |
| `svc_i_repeated_slow` | 3 × score 40: repeated |
| `svc_j_crash_loop` | crash loop Info line, no finding |
| `svc_k_early_varying_frames` | 3 × score 64: early crashes at different locations are not a crash loop |
| `svc_l_crash_loop_gc` | crash loop Info line, 3 × score 46: GC + exposure |
| `svc_m_repeated_gc_exposed` | 3 × score 54: repeated + GC + exposure |
| `svc_n_repeated_exposed` | 3 × score 46: repeated + exposure |
| `svc_o_repeated_gc_arm` | 3 × score 52: repeated + GC |

Verified with THOR 11.0.0-rc.3 on macOS (arm64).

## Writing your own

The pattern (meta rule trigger, directory listing from a hook, per-directory cache, time window) is described in
the `thor-plugins` skill of [Nextron-Labs/thor-skill](https://github.com/Nextron-Labs/thor-skill). The plugin API
is at [NextronSystems/thor-plugin](https://github.com/NextronSystems/thor-plugin).

## License

MIT, see [LICENSE](LICENSE).
