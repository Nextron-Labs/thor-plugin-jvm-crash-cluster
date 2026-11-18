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
Time: Wed Nov 18 10:00:00 2026 UTC elapsed time: 412.337 seconds (0d 0h 6m 52s)

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

CPU: total 8 (initial active 8) (4 cores per cpu, 2 threads per core) family 6 model 106 stepping 6 microcode 0xd0003a5, cx8, cmov, fxsr, ht, mmx, sse, sse2, sse3, ssse3, sse4.1, sse4.2, popcnt, lzcnt, tsc, tscinvbit, avx, avx2, aes, erms, clmul, bmi1, bmi2, adx, avx512f, avx512dq, avx512cd, avx512bw, avx512vl, sha, fma, vzeroupper, avx512_vpopcntdq, avx512_vpclmulqdq, avx512_vaes, avx512_vnni, clflush, clflushopt, clwb, avx512_vbmi2, avx512_vbmi{cpuextra}
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


def write(path, text, mtime):
    with open(path, "w", encoding="ascii") as f:
        f.write(text)
    ts = mtime.timestamp()
    os.utime(path, (ts, ts))


def crash(path, pid, mtime, gc=True, arch="linux-amd64", jvmargs="", vbmi=True):
    text = TEMPLATE.format(
        error="SIGSEGV",
        pid=pid,
        tid=pid + 37,
        arch=arch,
        frame=GC_FRAME if gc else APP_FRAME,
        thread=GC_THREAD if gc else APP_THREAD,
        vmop="VM_Operation (0x00007f3a3cdfe960): G1CollectForAllocation, mode: safepoint, requested by thread 0x00007f3a1402c1d0\n" if gc else "",
        jvmargs=jvmargs,
        cpuextra="" if vbmi else "",
    )
    if not vbmi:
        text = text.replace(", avx512_vbmi2, avx512_vbmi", "")
    write(path, text, mtime)


def main():
    out = sys.argv[1]
    base = datetime(2026, 11, 18, 10, 0, 0)

    # A: burst of 4 GC crashes within 31 minutes, exposed config -> cluster + GC + exposure
    d = os.path.join(out, "svc_a_burst_gc_exposed"); os.makedirs(d, exist_ok=True)
    for i, minutes in enumerate([0, 7, 15, 31]):
        pid = 4100 + i * 13
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=minutes))

    # B: single non-GC crash -> info only, no finding
    d = os.path.join(out, "svc_b_single"); os.makedirs(d, exist_ok=True)
    crash(os.path.join(d, "hs_err_pid5200.log"), 5200, base, gc=False)

    # C: crash loop of native OOM logs -> ignored
    d = os.path.join(out, "svc_c_native_oom"); os.makedirs(d, exist_ok=True)
    for i in range(4):
        pid = 6100 + i
        write(os.path.join(d, f"hs_err_pid{pid}.log"), OOM.format(pid=pid, tid=pid + 1), base + timedelta(minutes=i * 2))

    # D: burst of non-GC crashes, mitigation flag set -> cluster only
    d = os.path.join(out, "svc_d_burst_mitigated"); os.makedirs(d, exist_ok=True)
    for i in range(3):
        pid = 7100 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=i * 9), gc=False, jvmargs="-XX:-UseBASE64Intrinsics")

    # E: three non-GC crashes spread over days -> no cluster, info only
    d = os.path.join(out, "svc_e_spread"); os.makedirs(d, exist_ok=True)
    for i in range(3):
        pid = 8100 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base - timedelta(days=i * 3), gc=False)

    # F: renamed via -XX:ErrorFile, burst on ARM64 -> cluster + GC, no exposure
    d = os.path.join(out, "svc_f_renamed_arm"); os.makedirs(d, exist_ok=True)
    for i in range(3):
        pid = 9100 + i
        crash(os.path.join(d, f"jvm_crash_{pid}.log"), pid, base + timedelta(minutes=i * 4), arch="linux-aarch64", vbmi=False)

    # G: single GC crash, exposed config -> GC + exposure, no burst (Notice)
    d = os.path.join(out, "svc_g_single_gc_exposed"); os.makedirs(d, exist_ok=True)
    crash(os.path.join(d, "hs_err_pid9200.log"), 9200, base)

    # H: burst of non-GC crashes, exposed config -> burst + exposure
    d = os.path.join(out, "svc_h_burst_exposed"); os.makedirs(d, exist_ok=True)
    for i in range(3):
        pid = 9300 + i
        crash(os.path.join(d, f"hs_err_pid{pid}.log"), pid, base + timedelta(minutes=i * 5), gc=False)

    print("fixtures written to", out)


if __name__ == "__main__":
    main()
