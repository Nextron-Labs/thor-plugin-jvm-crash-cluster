// JVMCrashCluster - THOR v11 plugin
//
// Flags HotSpot fatal error logs (hs_err_pid*.log) that occur in bursts.
// A single JVM crash is usually a bug or a hardware problem. Several crashes of
// the same service within a short time span are a typical side effect of failed
// memory corruption exploitation attempts that get retried until they succeed
// (e.g. CVE-2026-114938 "Java4Shell"), and that is something a filename IOC or
// a YARA rule cannot express, because it needs the context of the directory.
//
// How it works
//   - A score 0 meta YARA rule tags every file that starts with the HotSpot
//     fatal error header (independent of the file name, -XX:ErrorFile can
//     rename it).
//   - On the first match in a directory, the plugin lists that directory,
//     parses all sibling crash logs (modification time, JVM uptime at the
//     crash, problematic frame) and caches the result.
//   - Two time windows: clusterMinCount crashes within burstWindow make a
//     burst, within repeatWindow a slower series of repeated crashes.
//   - A window in which every crash happened shortly after JVM start-up at the
//     same frame is a crash loop (broken configuration, JDK or native library)
//     and does not count.
//   - Supporting reasons: crash inside a GC thread / GC code (typical for heap
//     corruption) and a host / JVM configuration that is exposed to
//     CVE-2026-114938 (x86-64, AVX-512 VBMI, no mitigation flag).
//
// Native out-of-memory crash logs are ignored. They come in crash loops on
// misconfigured systems and are a common false positive source.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NextronSystems/jsonlog/thorlog/v3"
	thor "github.com/NextronSystems/thor-plugin"
)

// ---------------------------------------------------------------------------
// Tuning
// ---------------------------------------------------------------------------

const (
	burstWindow     = 15 * time.Minute // fast tier: retried attempts against a service that restarts quickly
	repeatWindow    = 60 * time.Minute // slow tier: slow-starting services or paced attempts
	clusterMinCount = 3                // crashes within a window that make a burst / series

	// A window is a crash loop if every crash happened within this many seconds
	// after JVM start-up and all crashes share the same (normalized) frame.
	crashLoopMaxUptime = 120.0

	scoreBurst    = 60 // >= clusterMinCount crashes within burstWindow
	scoreRepeated = 40 // >= clusterMinCount crashes within repeatWindow
	scoreGCCrash  = 40 // crash in GC thread / GC code (heap corruption)
	scoreExposure = 20 // only added on top of one of the above

	maxDirEntries  = 5000    // directory entries inspected per directory
	maxSiblingHead = 4096    // bytes read from sibling files for the header check
	maxReportBytes = 8 << 20 // bytes read from each crash log
	maxListedFiles = 10      // sibling names quoted in the reason text

	ruleTag   = "JVMCRASHLOG"
	ruleDate  = "2026-11-18"
	ruleAuth  = "Florian Roth"
	reference = "https://calif.io/java4shell"
)

const crashHeader = "A fatal error has been detected by the Java Runtime Environment"
const nativeOOMHeader = "There is insufficient memory for the Java Runtime Environment to continue"

const triggerRule = `
rule JVM_Fatal_Error_Log : JVMCRASHLOG {
	meta:
		description = "HotSpot fatal error log (hs_err_pid*.log), trigger for the JVMCrashCluster plugin"
		author = "Florian Roth"
		date = "2026-11-18"
		score = 0
	strings:
		$h = "# A fatal error has been detected by the Java Runtime Environment" ascii
	condition:
		$h in (0..256)
}
`

// ---------------------------------------------------------------------------
// Crash log parsing
// ---------------------------------------------------------------------------

var (
	reError       = regexp.MustCompile(`(?m)^#\s+((?:SIG[A-Z]+|EXCEPTION_[A-Z_]+|Internal Error)[^\r\n]*)`)
	reJRE         = regexp.MustCompile(`(?m)^# JRE version: ([^\r\n]+)`)
	reVM          = regexp.MustCompile(`(?m)^# Java VM: ([^\r\n]+)`)
	reFrame       = regexp.MustCompile(`(?m)^# Problematic frame:\r?\n#\s+([^\r\n]+)`)
	reThread      = regexp.MustCompile(`(?m)^Current thread \([^)]*\):\s+([^\r\n]+)`)
	reVMOp        = regexp.MustCompile(`(?m)^VM_Operation \([^)]*\):\s+([^\r\n,]+)`)
	reCmdLine     = regexp.MustCompile(`(?m)^Command Line: ([^\r\n]+)`)
	reJavaCmd     = regexp.MustCompile(`(?m)^java_command: ([^\r\n]+)`)
	reJVMArgs     = regexp.MustCompile(`(?m)^jvm_args: ([^\r\n]+)`)
	reUptime      = regexp.MustCompile(`elapsed time: ([0-9]+(?:\.[0-9]+)?) seconds`)
	reVBMI        = regexp.MustCompile(`\bavx512_?vbmi\b`)
	reX86         = regexp.MustCompile(`amd64|x86_64`)
	reNoIntrinsic = regexp.MustCompile(`-XX:-UseBASE64Intrinsics\b`)
	reLowAVX      = regexp.MustCompile(`-XX:UseAVX=[0-2]\b`)

	// Frame normalization: addresses, offsets and compile IDs change with every JVM start.
	reHexNum = regexp.MustCompile(`0x[0-9a-fA-F]+`)
	reDecNum = regexp.MustCompile(`\b[0-9]+\b`)

	// Crashing thread is a GC worker (JDK 8 to 25 naming)
	reGCThread = regexp.MustCompile(`GC Thread#|"G1 [A-Za-z]|GCTaskThread|ConcurrentGCThread|"(?:ZGC|Shenandoah|PS|CMS) `)
	// Safepoint VM operation is a collection
	reGCVMOp = regexp.MustCompile(`G1Collect|G1Pause|G1TryInitiateConcMark|CollectForMetadataAllocation|GenCollect|ParallelGCFailedAllocation`)
	// Problematic frame is in GC or object model code
	reGCFrame = regexp.MustCompile(`\bG1[A-Z]\w*::|\bPS(?:Promotion|Scavenge|ParallelCompact)\w*::|\boopDesc::|\bOopMapSet::|\bMarkSweep::|\bHeapRegion\w*::`)
)

type crashReport struct {
	errorLine string
	jre       string
	vm        string
	frame     string
	thread    string
	vmOp      string
	command   string
	jvmArgs   string
	uptime    float64 // JVM uptime at the crash in seconds, -1 if unknown
	nativeOOM bool
	cpuKnown  bool
	vbmi      bool
	x86       bool
}

func firstGroup(re *regexp.Regexp, data []byte) string {
	m := re.FindSubmatch(data)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

func parseReport(data []byte) crashReport {
	r := crashReport{
		errorLine: firstGroup(reError, data),
		jre:       firstGroup(reJRE, data),
		vm:        firstGroup(reVM, data),
		frame:     firstGroup(reFrame, data),
		thread:    firstGroup(reThread, data),
		vmOp:      firstGroup(reVMOp, data),
		command:   firstGroup(reCmdLine, data),
		jvmArgs:   firstGroup(reJVMArgs, data),
		uptime:    -1,
		nativeOOM: bytes.Contains(data, []byte(nativeOOMHeader)),
	}
	if r.command == "" {
		r.command = firstGroup(reJavaCmd, data)
	}
	// JDK 11+: "Time: ... elapsed time: 412.337 seconds (...)", JDK 8: "elapsed time: 412 seconds (...)"
	if s := firstGroup(reUptime, data); s != "" {
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			r.uptime = v
		}
	}
	r.vbmi = reVBMI.Match(data)
	// CPU details are in the System section ("CPU:" line, /proc/cpuinfo flags on Linux)
	r.cpuKnown = r.vbmi || bytes.Contains(data, []byte("\nCPU:")) || bytes.Contains(data, []byte("flags\t"))
	r.x86 = reX86.MatchString(r.vm)
	return r
}

// normalizeFrame removes addresses, offsets and compile IDs so that the same
// crash location compares equal across JVM restarts.
func normalizeFrame(frame string) string {
	f := reHexNum.ReplaceAllString(frame, "")
	f = reDecNum.ReplaceAllString(f, "")
	return strings.Join(strings.Fields(f), " ")
}

func (r crashReport) gcCrash() bool {
	return reGCThread.MatchString(r.thread) || reGCVMOp.MatchString(r.vmOp) || reGCFrame.MatchString(r.frame)
}

func (r crashReport) mitigated() bool {
	return reNoIntrinsic.MatchString(r.jvmArgs) || reLowAVX.MatchString(r.jvmArgs)
}

// exposed reports whether the crashed JVM ran on a configuration affected by
// CVE-2026-114938 (x86-64 + AVX-512 VBMI + Base64 intrinsics not disabled).
// The JDK version is not checked, fixed builds are reported in the reason text.
func (r crashReport) exposed() bool {
	return r.x86 && r.vbmi && !r.mitigated()
}

// exposureVerdict is added to every reason text, because THOR shows only the
// first two reasons of a finding by default (--alert-reason-limit).
func (r crashReport) exposureVerdict() string {
	switch {
	case r.mitigated():
		return "not exposed (mitigation flag set)"
	case r.vm != "" && !r.x86:
		return "not exposed (not x86-64)"
	case r.cpuKnown && !r.vbmi:
		return "not exposed (no AVX-512 VBMI)"
	case r.exposed():
		return "exposed configuration, check JDK patch level"
	default:
		return "unknown"
	}
}

// readContent reads up to limit bytes; a short read still returns what was read.
func readContent(content thor.ObjectReader, limit int64) []byte {
	size := content.Size()
	if size > limit {
		size = limit
	}
	if size <= 0 {
		return nil
	}
	buf := make([]byte, size)
	n, _ := content.ReadAt(buf, 0)
	return buf[:n]
}

func readHead(path string, limit int) []byte {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, limit)
	n, _ := io.ReadFull(f, buf)
	return buf[:n]
}

// ---------------------------------------------------------------------------
// Directory clustering
// ---------------------------------------------------------------------------

type crashFile struct {
	name   string
	mtime  time.Time
	uptime float64 // seconds, -1 if unknown
	frame  string  // normalized problematic frame
}

type tierResult struct {
	window   time.Duration
	maxCount int             // highest number of crashes within one counted window
	members  map[string]bool // crash logs that are part of at least one counted window
	first    time.Time       // first crash of the densest window
	last     time.Time       // last crash of the densest window
	names    []string        // crash logs of the densest window
}

type dirCluster struct {
	total    int // crash logs in the directory (native OOM excluded)
	burst    *tierResult
	repeated *tierResult
}

var (
	cacheMu sync.Mutex
	cache   = map[string]*dirCluster{}
)

func clusterFor(dir string, logger thor.Logger) *dirCluster {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if c, ok := cache[dir]; ok {
		return c
	}
	c := computeCluster(dir, logger)
	cache[dir] = c
	return c
}

func newTier(window time.Duration) *tierResult {
	return &tierResult{window: window, members: map[string]bool{}}
}

// isCrashLoop reports whether all crashes of a window happened shortly after
// JVM start-up at the same frame. Unknown uptimes or frames never count as
// crash loop, so missing data keeps the detection.
func isCrashLoop(w []crashFile) bool {
	for _, c := range w {
		if c.uptime < 0 || c.uptime > crashLoopMaxUptime || c.frame == "" || c.frame != w[0].frame {
			return false
		}
	}
	return true
}

// findWindows slides a window over the crashes (sorted by mtime). Every crash
// in a window with at least clusterMinCount crashes becomes a member, unless
// that window is a crash loop.
func findWindows(crashes []crashFile, window time.Duration, loops map[string]bool) *tierResult {
	t := newTier(window)
	start := 0
	bestStart, bestEnd := 0, -1
	for end := range crashes {
		for crashes[end].mtime.Sub(crashes[start].mtime) > window {
			start++
		}
		count := end - start + 1
		if count < clusterMinCount {
			continue
		}
		if isCrashLoop(crashes[start : end+1]) {
			for k := start; k <= end; k++ {
				loops[crashes[k].name] = true
			}
			continue
		}
		for k := start; k <= end; k++ {
			t.members[crashes[k].name] = true
		}
		if count > t.maxCount {
			t.maxCount = count
			bestStart, bestEnd = start, end
		}
	}
	if bestEnd >= 0 {
		t.first = crashes[bestStart].mtime
		t.last = crashes[bestEnd].mtime
		for k := bestStart; k <= bestEnd; k++ {
			t.names = append(t.names, crashes[k].name)
		}
	}
	return t
}

func computeCluster(dir string, logger thor.Logger) *dirCluster {
	c := &dirCluster{burst: newTier(burstWindow), repeated: newTier(repeatWindow)}
	entries, err := os.ReadDir(dir)
	if err != nil {
		// e.g. file inside an archive
		logger.Debug("JVMCrashCluster: cannot list directory", "dir", dir, "error", err.Error())
		return c
	}

	var crashes []crashFile
	for i, e := range entries {
		if i >= maxDirEntries {
			logger.Debug("JVMCrashCluster: directory entry limit reached", "dir", dir, "limit", maxDirEntries)
			break
		}
		if !e.Type().IsRegular() {
			continue
		}
		lname := strings.ToLower(e.Name())
		if !strings.HasSuffix(lname, ".log") && !strings.Contains(lname, "hs_err") {
			continue
		}
		path := filepath.Join(dir, e.Name())
		head := readHead(path, maxSiblingHead)
		if !bytes.Contains(head, []byte(crashHeader)) || bytes.Contains(head, []byte(nativeOOMHeader)) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		size := info.Size()
		if size > maxReportBytes {
			size = maxReportBytes
		}
		r := parseReport(readHead(path, int(size)))
		crashes = append(crashes, crashFile{
			name:   e.Name(),
			mtime:  info.ModTime(),
			uptime: r.uptime,
			frame:  normalizeFrame(r.frame),
		})
	}
	c.total = len(crashes)
	if len(crashes) < clusterMinCount {
		return c
	}

	sort.Slice(crashes, func(i, j int) bool { return crashes[i].mtime.Before(crashes[j].mtime) })

	loops := map[string]bool{}
	c.burst = findWindows(crashes, burstWindow, loops)
	c.repeated = findWindows(crashes, repeatWindow, loops)

	// Report crash loops once per directory (only files that are not counted otherwise)
	var loopNames []string
	loopFrame := ""
	for _, cr := range crashes {
		if loops[cr.name] && !c.burst.members[cr.name] && !c.repeated.members[cr.name] {
			loopNames = append(loopNames, cr.name)
			loopFrame = cr.frame
		}
	}
	if len(loopNames) > 0 {
		logger.Info("JVMCrashCluster: JVM crash loop at start-up, not counted as burst",
			"dir", dir, "count", len(loopNames), "frame", truncate(loopFrame, 160),
			"files", truncate(strings.Join(loopNames, ", "), 300))
	}
	return c
}

// ---------------------------------------------------------------------------
// Reasons
// ---------------------------------------------------------------------------

// NewReason sets the object type header; a plain thorlog.Reason{} literal
// shows up with "type": "" in the JSON output.
func newReason(rule string, score int64, summary, description string) thorlog.Reason {
	return thorlog.NewReason(summary, thorlog.Signature{
		Score:           score,
		Ref:             thorlog.StringList{reference},
		Type:            thorlog.Custom,
		Class:           thorlog.ClassInternalHeuristic,
		Date:            ruleDate,
		Tags:            thorlog.StringList{"JVM", "CRASH", "EXPLOITATION", "CVE-2026-114938"},
		Rulename:        rule,
		LongDescription: description,
		Author:          ruleAuth,
	}, nil)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func formatUptime(seconds float64) string {
	if seconds < 0 {
		return "unknown"
	}
	return (time.Duration(seconds) * time.Second).String()
}

func context(r crashReport) string {
	parts := []string{}
	if r.errorLine != "" {
		parts = append(parts, "error: "+truncate(r.errorLine, 120))
	}
	parts = append(parts, "uptime: "+formatUptime(r.uptime))
	if r.jre != "" {
		parts = append(parts, "jre: "+truncate(r.jre, 120))
	}
	if r.command != "" {
		parts = append(parts, "command: "+truncate(r.command, 200))
	}
	parts = append(parts, "CVE-2026-114938: "+r.exposureVerdict())
	return strings.Join(parts, " | ")
}

func windowSummary(label string, t *tierResult, total int, r crashReport) string {
	names := t.names
	more := ""
	if len(names) > maxListedFiles {
		more = fmt.Sprintf(" (+%d more)", len(names)-maxListedFiles)
		names = names[:maxListedFiles]
	}
	return fmt.Sprintf("%s: %d fatal error logs within %s in the same directory (window %d min, %d crash logs in total), %s to %s, files: %s%s | %s",
		label, t.maxCount, t.last.Sub(t.first).Round(time.Second), int(t.window.Minutes()), total,
		t.first.UTC().Format(time.RFC3339), t.last.UTC().Format(time.RFC3339),
		strings.Join(names, ", "), more, context(r))
}

func onCrashLog(scanner thor.Scanner, obj thor.MatchingObject) {
	file, ok := obj.Object.(*thorlog.File)
	if !ok || obj.Content == nil {
		return
	}
	r := parseReport(readContent(obj.Content, maxReportBytes))
	if r.nativeOOM {
		scanner.Debug("JVMCrashCluster: ignoring native out-of-memory crash log", "file", file.Path)
		return
	}

	scanner.Info("JVM fatal error log found",
		"file", file.Path, "error", r.errorLine, "uptime", formatUptime(r.uptime), "jre", r.jre,
		"thread", truncate(r.thread, 120), "frame", truncate(r.frame, 160), "command", truncate(r.command, 200))

	flagged := false

	// 1) burst or slower series of crashes in the same directory (crash loops excluded)
	c := clusterFor(filepath.Dir(file.Path), scanner)
	name := filepath.Base(file.Path)
	switch {
	case c.burst.members[name]:
		scanner.AddReason(newReason("JVM_Crash_Log_Burst", scoreBurst,
			windowSummary("JVM crash burst", c.burst, c.total, r),
			fmt.Sprintf("%d or more HotSpot fatal error logs within %d minutes in one directory, not explained by a crash loop at JVM start-up. Repeated JVM crashes of an exposed service are a side effect of retried memory corruption exploitation attempts.",
				clusterMinCount, int(burstWindow.Minutes()))))
		flagged = true
	case c.repeated.members[name]:
		scanner.AddReason(newReason("JVM_Crash_Log_Repeated", scoreRepeated,
			windowSummary("Repeated JVM crashes", c.repeated, c.total, r),
			fmt.Sprintf("%d or more HotSpot fatal error logs within %d minutes in one directory, not explained by a crash loop at JVM start-up. Slower than a burst: a service with a long start-up time or paced exploitation attempts.",
				clusterMinCount, int(repeatWindow.Minutes()))))
		flagged = true
	}

	// 2) crash in garbage collection, typical for a corrupted heap
	if r.gcCrash() {
		summary := fmt.Sprintf("JVM crashed in garbage collection, possible heap corruption | thread: %s | frame: %s | vm_operation: %s | %s",
			truncate(r.thread, 120), truncate(r.frame, 160), r.vmOp, context(r))
		scanner.AddReason(newReason("JVM_Crash_In_Garbage_Collection", scoreGCCrash, summary,
			"The JVM crashed inside a garbage collector thread or GC code. Heap corruption caused by an out-of-bounds write usually surfaces when the collector walks the damaged objects."))
		flagged = true
	}

	// 3) host and JVM configuration exposed to CVE-2026-114938
	if flagged && r.exposed() {
		summary := fmt.Sprintf("Crashed JVM ran on an x86-64 CPU with AVX-512 VBMI without -XX:-UseBASE64Intrinsics or -XX:UseAVX=2, check whether the JDK build is patched for CVE-2026-114938 | %s", context(r))
		scanner.AddReason(newReason("JVM_Crash_CVE_2026_114938_Exposed_Config", scoreExposure, summary,
			"The crash log shows a CPU and JVM configuration on which the vulnerable AVX-512 Base64 intrinsic is active. The JDK version has to be compared against the fixed releases."))
	}
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func Init(config thor.Configuration, logger thor.Logger, actions thor.RegisterActions) {
	actions.AddYaraRule(thor.TypeMeta, triggerRule)
	actions.AddRuleHook(ruleTag, onCrashLog)
	logger.Info("JVMCrashCluster plugin loaded",
		"burst_window", burstWindow.String(), "repeat_window", repeatWindow.String(),
		"min_count", clusterMinCount, "crash_loop_max_uptime_s", crashLoopMaxUptime)
}
