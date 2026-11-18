#!/usr/bin/env python3
"""Create synthetic HotSpot fatal error logs to test the JVMCrashCluster plugin.

Usage: python3 -I make_fixtures.py <output-dir>
"""
import os
import sys
from datetime import datetime, timedelta

TEMPLATE = """#
# A fatal error has been detected by the Java Runtime Environment:
#
#  {error} (0xb) at pc=0x00007f3a1c2d5e2a, pid={pid}, tid={tid}
#
# JRE version: OpenJDK Runtime Environment Temurin-21.0.8+9 (21.0.8+9) (build 21.0.8+9-LTS)
# Java VM: OpenJDK 64-Bit Server VM Temurin-21.0.8+9 (21.0.8+9-LTS, mixed mode, sharing, tiered, compressed oops, compressed class ptrs, g1 gc, {arch})
# Problematic frame:
# {frame}
#
# Core dump will be written. Default location: /opt/app/core.{pid}
#
# If you would like to submit a bug report, please visit:
#   https://github.com/adoptium/adoptium-support/issues
#

---------------  S U M M A R Y ------------

Command Line: -Xms1g -Xmx2g {jvmargs} org.keycloak.quarkus._private.IDELauncher start

Host: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz, 8 cores, 31G, Ubuntu 22.04.4 LTS
Time: Wed Nov 18 10:00:00 2026 UTC elapsed time: {uptime:.3f} seconds ({uptime_hms})

---------------  T H R E A D  ---------------

Current thread (0x00007f3a14029a10):  {thread} [id={tid}, stack(0x00007f3a01a00000,0x00007f3a01b00000) (1024K)]

Stack: [0x00007f3a01a00000,0x00007f3a01b00000],  sp=0x00007f3a01afe9b0,  free space=1018k
Native frames: (J=compiled Java code, j=interpreted, Vv=VM code, C=native code)
V  [libjvm.so+0x5d1e2a]
{vmop}
---------------  P R O C E S S  ---------------

jvm_args: -Xms1g -Xmx2g {jvmargs}
java_command: org.keycloak.quarkus._private.IDELauncher start

---------------  S Y S T E M  ---------------

OS:
DISTRIB_DESCRIPTION="Ubuntu 22.04.4 LTS"

CPU: total 8 (initial active 8) (4 cores per cpu, 2 threads per core) family 6 model 106 stepping 6 microcode 0xd0003a5, cx8, cmov, fxsr, ht, mmx, sse, sse2, sse3, ssse3, sse4.1, sse4.2, popcnt, lzcnt, tsc, tscinvbit, avx, avx2, aes, erms, clmul, bmi1, bmi2, adx, avx512f, avx512dq, avx512cd, avx512bw, avx512vl, sha, fma, vzeroupper, avx512_vpopcntdq, avx512_vpclmulqdq, avx512_vaes, avx512_vnni, clflush, clflushopt, clwb, avx512_vbmi2, avx512_vbmi
"""

OOM = """#
# There is insufficient memory for the Java Runtime Environment to continue.
# Native memory allocation (mmap) failed to map 65536 bytes for committing reserved memory.
# Possible reasons:
#   The system is out of physical RAM or swap space
#
#  Out of Memory Error (os_linux.cpp:2830), pid={pid}, tid={tid}
#
# JRE version: OpenJDK Runtime Environment Temurin-21.0.8+9 (21.0.8+9) (build 21.0.8+9-LTS)
"""

GC_THREAD = 'WorkerThread "GC Thread#3"'
GC_FRAME = "V  [libjvm.so+0x5d1e2a]  G1ParScanThreadState::trim_queue_to_threshold(unsigned int)+0x2fa"
APP_THREAD = 'JavaThread "executor-thread-12" [_thread_in_Java'
APP_FRAME = "J 4711 c2 org.example.Util.process([B)V (88 bytes) @ 0x00007f3a0d2e4c11 [0x00007f3a0d2e4b80+0x0000000000000091]"
# Same crash location, but compile ID and addresses differ after every JVM start
APP_FRAME_RESTART = "J {cid} c2 org.example.Util.process([B)V (88 bytes) @ 0x{addr:016x} [0x{base:016x}+0x0000000000000091]"
# Different crash locations
VARYING_FRAMES = [
    "J 6011 c2 java.util.HashMap.putVal(ILjava/lang/Object;Ljava/lang/Object;ZZ)Ljava/lang/Object; java.base@21.0.8 (300 bytes) @ 0x00007f3a0d31a2b4 [0x00007f3a0d319f80+0x0000000000000334]",
    "J 7002 c2 com.fasterxml.jackson.core.json.UTF8StreamJsonParser.nextToken()Lcom/fasterxml/jackson/core/JsonToken; (1077 bytes) @ 0x00007f3a0d4b8e10 [0x00007f3a0d4b8a40+0x00000000000003d0]",
    "V  [libjvm.so+0x3c4d5e]  CompileBroker::invoke_compiler_on_method(CompileTask*)+0x4ad",
]
DEFAULT_UPTIME = 412.337  # long-running service


def hms(seconds):
    s = int(seconds)
    return f"{s // 86400}d {s % 86400 // 3600}h {s % 3600 // 60}m {s % 60}s"


def write(path, text, mtime):
    with open(path, "w", encoding="ascii") as f:
        f.write(text)
    ts = mtime.timestamp()
    os.utime(path, (ts, ts))


def crash(path, pid, mtime, gc=True, arch="linux-amd64", jvmargs="", vbmi=True, uptime=DEFAULT_UPTIME, frame=None):
    if frame is None:
        frame = GC_FRAME if gc else APP_FRAME
    text = TEMPLATE.format(
        error="SIGSEGV",
        pid=pid,
        tid=pid + 37,
        arch=arch,
        frame=frame,
        thread=GC_THREAD if gc else APP_THREAD,
        vmop="VM_Operation (0x00007f3a3cdfe960): G1CollectForAllocation, mode: safepoint, requested by thread 0x00007f3a1402c1d0\n" if gc else "",
        jvmargs=jvmargs,
        uptime=uptime,
        uptime_hms=hms(uptime),
    )
    if not vbmi:
        text = text.replace(", avx512_vbmi2, avx512_vbmi", "")
    write(path, text, mtime)


def folder(out, name):
    d = os.path.join(out, name)
    os.makedirs(d, exist_ok=True)
    return d


def main():
    out = sys.argv[1]
    base = datetime(2026, 11, 18, 10, 0, 0)
    mitigated = "-XX:-UseBASE64Intrinsics"

    # A: 4 GC crashes within 13 minutes, exposed config -> burst + GC + exposure
    d = folder(out, "svc_a_burst_gc_exposed")
    for i, minutes in enumerate([0, 4, 9, 13]):
        pid = 4100 + i * 13
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=minutes))

    # B: single non-GC crash -> Info only
    d = folder(out, "svc_b_single")
    crash(os.path.join(d, "hs_err_pid5200.log"), 5200, base, gc=False)

    # C: native OOM crash loop -> ignored
    d = folder(out, "svc_c_native_oom")
    for i in range(4):
        pid = 6100 + i
        write(os.path.join(d, f"hs_err_pid{pid}.log"), OOM.format(pid=pid, tid=pid + 1), base + timedelta(minutes=i * 2))

    # D: burst of non-GC crashes, mitigation flag set -> burst only
    d = folder(out, "svc_d_burst_mitigated")
    for i in range(3):
        pid = 7100 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=i * 5), gc=False, jvmargs=mitigated)

    # E: three non-GC crashes spread over days -> Info only
    d = folder(out, "svc_e_spread")
    for i in range(3):
        pid = 8100 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base - timedelta(days=i * 3), gc=False)

    # F: renamed via -XX:ErrorFile, GC crashes on ARM64 -> burst + GC, not exposed
    d = folder(out, "svc_f_renamed_arm")
    for i in range(3):
        pid = 9100 + i
        crash(os.path.join(d, f"jvm_crash_{pid}.log"), pid, base + timedelta(minutes=i * 4), arch="linux-aarch64", vbmi=False)

    # G: single GC crash, exposed config -> GC + exposure, no burst
    d = folder(out, "svc_g_single_gc_exposed")
    crash(os.path.join(d, "hs_err_pid9200.log"), 9200, base)

    # H: burst of non-GC crashes, exposed config -> burst + exposure
    d = folder(out, "svc_h_burst_exposed")
    for i in range(3):
        pid = 9300 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=i * 5), gc=False)

    # I: 3 non-GC crashes within 50 minutes, mitigated -> repeated (slow tier) only
    d = folder(out, "svc_i_repeated_slow")
    for i in range(3):
        pid = 9400 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=i * 25), gc=False, jvmargs=mitigated)

    # J: crash loop at start-up (uptime seconds, same frame, new compile IDs) -> no burst, Info only
    d = folder(out, "svc_j_crash_loop")
    for i in range(4):
        pid = 9500 + i
        frame = APP_FRAME_RESTART.format(cid=4711 + i * 3, addr=0x7F3A0D2E4C11 + i * 0x1000, base=0x7F3A0D2E4B80 + i * 0x1000)
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=i), gc=False, uptime=3.2 + i, frame=frame)

    # K: early crashes (uptime < 120 s) at different frames -> not a crash loop: burst + exposure
    d = folder(out, "svc_k_early_varying_frames")
    for i, frame in enumerate(VARYING_FRAMES):
        pid = 9600 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=i * 4), gc=False, uptime=25.0 + i * 7, frame=frame)

    # L: crash loop in GC code -> no burst, but GC + exposure per file
    d = folder(out, "svc_l_crash_loop_gc")
    for i in range(3):
        pid = 9700 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=i), uptime=5.0 + i)

    # M: slow series of GC crashes, exposed config -> repeated + GC + exposure
    d = folder(out, "svc_m_repeated_gc_exposed")
    for i in range(3):
        pid = 9800 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=i * 25))

    # N: slow series of non-GC crashes, exposed config -> repeated + exposure
    d = folder(out, "svc_n_repeated_exposed")
    for i in range(3):
        pid = 9900 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=i * 25), gc=False)

    # O: slow series of GC crashes on ARM64 -> repeated + GC, not exposed
    d = folder(out, "svc_o_repeated_gc_arm")
    for i in range(3):
        pid = 9950 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=i * 25), arch="linux-aarch64", vbmi=False)

    print("fixtures written to", out)


if __name__ == "__main__":
    main()
