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
| `JVM_Crash_Log_Burst` | 60 | 3 or more crash logs within 60 minutes in the same directory. Every file of a dense window is flagged. |
| `JVM_Crash_In_Garbage_Collection` | 40 | The crashing thread is a GC worker, the safepoint VM operation is a collection, or the problematic frame is in G1 / GC / object model code. Heap corruption usually surfaces there. |
| `JVM_Crash_CVE_2026_114938_Exposed_Config` | 20 | Only on top of one of the above: x86-64, AVX-512 VBMI in the CPU features, and neither `-XX:-UseBASE64Intrinsics` nor `-XX:UseAVX=0..2` set |

THOR combines sub-scores with diminishing returns, so they don't simply add up. Results with THOR 11.0.0-rc.3:

| Situation | Score | Level |
|---|---|---|
| Burst | 60 | Warning |
| Burst + exposed configuration | 64 | Warning |
| Burst + crash in GC code | 68 | Warning |
| Burst + crash in GC code + exposed configuration | 70 | Warning |
| Single crash in GC code | 40 (46 on an exposed configuration) | Notice |
| Single crash elsewhere, or crashes spread out over time | – | no finding, Info line only |
| Native out-of-memory crash log | – | ignored |

Every reason text carries the error line, the JRE version, the command line and a CVE-2026-114938 verdict
(`exposed configuration, check JDK patch level` / `not exposed (...)` / `unknown`). The verdict is part of the text
because THOR shows only two reasons per finding by default (`--alert-reason-limit`).

Example reason (shortened):

```
REASON_1: JVM crash burst: 4 fatal error logs within 31m0s in the same directory (4 in total),
  window 2026-11-18T09:00:00Z to 2026-11-18T09:31:00Z, files: hs_err_pid4100.log, hs_err_pid4113.log, ...
  | error: SIGSEGV (0xb) at pc=0x00007f3a1c2d5e2a, pid=4126, tid=4163
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
   - the `JRE version` and `Java VM` lines (the VM line includes the architecture, e.g. `linux-amd64`)
   - the problematic frame, the crashing thread (`Current thread`) and the running `VM_Operation`
   - the command line (`Command Line:`, falling back to `java_command:`) and `jvm_args`
   - the CPU features (HotSpot `CPU:` line and, on Linux, the `/proc/cpuinfo` flags)

   Native out-of-memory logs ("There is insufficient memory for the Java Runtime Environment to continue") stop
   here: no Info line, no reason, and they don't count towards bursts. They come in crash loops on misconfigured
   systems and are the main false positive source.
3. **Log it.** Every other crash log produces an Info line `JVM fatal error log found` with error, JRE, thread,
   frame and command, whether or not a reason fires.
4. **Check the folder.** On the first crash log in a directory, the plugin lists that directory once. It checks the
   first 4 KB of every `*.log` or `*hs_err*` sibling for the header, takes the modification times, and caches the
   result per directory. A sliding window over the sorted modification times finds dense windows; every file in
   one gets the burst reason.
5. **Check the crash itself.** The GC check uses the thread, VM operation and frame; the exposure check uses the
   architecture, CPU features and JVM arguments (see [Reasons](#reasons)).

## Tuning

Constants at the top of `plugin.go`: `clusterWindow`, `clusterMinCount`, the three scores, and the directory and read
limits.

## Limitations

- **Based on modification times.** Crash logs copied without preserved timestamps (e.g. from a collector ZIP) all
  get the copy time and look like a burst. Scan the original file system or a mounted image.
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

`test/make_fixtures.py` writes synthetic crash logs for eight cases:

```bash
python3 -I test/make_fixtures.py /tmp/jvm-fixtures
./thor-linux-64 --module Filescan --path /tmp/jvm-fixtures --alert-reason-limit 0 --no-thordb -e /tmp/thor-out
```

| Fixture | Expected |
|---|---|
| `svc_a_burst_gc_exposed` | 4 × score 70, all three reasons |
| `svc_b_single` | Info only |
| `svc_c_native_oom` | ignored |
| `svc_d_burst_mitigated` | 3 × score 60, burst only, verdict "not exposed (mitigation flag set)" |
| `svc_e_spread` | Info only |
| `svc_f_renamed_arm` | 3 × score 68, verdict "not exposed (not x86-64)" |
| `svc_g_single_gc_exposed` | 1 × score 46 (Notice), GC + exposure, no burst |
| `svc_h_burst_exposed` | 3 × score 64, burst + exposure |

Verified with THOR 11.0.0-rc.3 on macOS (arm64).

## Writing your own

The pattern (meta rule trigger, directory listing from a hook, per-directory cache, time window) is described in
the `thor-plugins` skill of [Nextron-Labs/thor-skill](https://github.com/Nextron-Labs/thor-skill). The plugin API
is at [NextronSystems/thor-plugin](https://github.com/NextronSystems/thor-plugin).

## License

MIT, see [LICENSE](LICENSE).
