/* M4 behaviour benchmark (Linux x86-64). One CSV row per measurement window.
 *
 *   gcc -O2 -o bench bench.c -lm
 *   ./bench <idle|cpu|mem|mixed> <window_ms> <n_windows> > out.csv
 *
 * CSV header (fixed contract, other tools depend on it):
 *   window,workload,elapsed_ms,cpuid_tsc,rdtsc_tsc,syscall_ns,pagefault_ns,seq_ns,stride_ns,rand_ns,
 *   sleep_jitter_us,ipc,dtlb_miss      (all on one line)
 *
 * window_ms is ONLY a probe-size scale factor (probe work is sized from it, clamped to 1..100 ms
 * equivalent); it is not a duration. elapsed_ms is the real wall time the window's probes took.
 * cpuid_tsc / rdtsc_tsc are TSC ticks (constant-rate counter), not core cycles.
 * sleep_jitter_us is the median absolute deviation (MAD, robust spread) of 100 us sleeps.
 * Background load (cpu/mem/mixed) runs in a forked child pinned to the same CPU as the probes.
 * Probes that the hardware or VM does not expose (perf counters) are written as nan.
 *
 * CSV number format: ipc, dtlb_miss and sleep_jitter_us use %.6g (6 significant digits) because they can be
 * tiny (dtlb_miss is misses per access, often < 1e-3) and a fixed number of decimals would round them to 0, which
 * the analysis treats as "not measured". The other columns use %.4f: they are 0.1..1e6 and never that small.
 *
 * stderr '#' lines (not part of the CSV):
 *   # cpu_model=... startup_ms=<n>   environment, printed once just before the first timed window.
 *                                    startup_ms = process start to that moment (allocation, Sattolo shuffle,
 *                                    load start, load steady-state wait, warm-up window): the real cost of
 *                                    one decision before any measurement.
 *   # load_dead=1 window=<k>         the load child died before the run ended (exit status 3): the "mixed"
 *                                    rows would otherwise be idle measurements. Discard the run.
 *   # load_alive=1                   printed at the end of a successful run.
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <errno.h>
#include <linux/perf_event.h>
#include <math.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#define MB (1UL << 20)
#define LINE 64
#define PAGE 4096
/* 256 MB: well above any LLC, so probes hit DRAM. Power of two (the load child masks offsets). */
#define BUF_SIZE (256 * MB)

static double now_ns(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC_RAW, &t);
    return t.tv_sec * 1e9 + t.tv_nsec;
}

static int cmp(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}

static double median(double *v, int n) {
    qsort(v, n, sizeof *v, cmp);
    return v[n / 2];
}

/* anonymous mapping, no transparent huge pages (so page-stride probes really see 4 KB pages) */
static void *xmap(size_t size) {
    void *m = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) { perror("mmap"); exit(1); }
    if (madvise(m, size, MADV_NOHUGEPAGE) != 0) perror("madvise(MADV_NOHUGEPAGE) (continuing)");
    return m;
}

/* ---- probes ---- */
static double p_cpuid(int reps) { /* TSC ticks per CPUID; always a VM exit under virtualization */
    double v[64];
    for (int i = 0; i < 64; i++) {
        unsigned a, b, c, d;
        _mm_lfence();
        uint64_t t0 = __rdtsc();
        _mm_lfence();
        for (int k = 0; k < reps; k++) __cpuid(0, a, b, c, d);
        _mm_lfence();
        uint64_t t1 = __rdtsc();
        _mm_lfence();
        v[i] = (double)(t1 - t0) / reps;
    }
    return median(v, 64);
}

static double p_rdtsc(void) { /* back-to-back RDTSC delta in TSC ticks (includes one LFENCE) */
    double v[256];
    for (int i = 0; i < 256; i++) {
        _mm_lfence();
        uint64_t a = __rdtsc();
        _mm_lfence();
        uint64_t b = __rdtsc();
        _mm_lfence();
        v[i] = (double)(b - a);
    }
    return median(v, 256);
}

static double p_syscall(int reps) {
    double v[32];
    for (int i = 0; i < 32; i++) {
        double t0 = now_ns();
        for (int k = 0; k < reps; k++) syscall(SYS_getppid);
        v[i] = (now_ns() - t0) / reps;
    }
    return median(v, 32);
}

static double p_pagefault(int pages) { /* ns per first-touch fault */
    double v[16];
    for (int i = 0; i < 16; i++) {
        char *m = xmap((size_t)pages * PAGE);
        double t0 = now_ns();
        for (int p = 0; p < pages; p++) m[(size_t)p * PAGE] = 1;
        v[i] = (now_ns() - t0) / pages;
        munmap(m, (size_t)pages * PAGE);
    }
    return median(v, 16);
}

static volatile uint64_t sink;

static double p_seq(char *buf, size_t size) { /* ns per cache line, sequential */
    double t0 = now_ns();
    uint64_t s = 0;
    for (size_t i = 0; i < size; i += LINE) s += buf[i];
    sink = s;
    return (now_ns() - t0) / (size / LINE);
}

#define STRIDE_STEP (PAGE + LINE)
#define STRIDE_REPS 4

static uint64_t stride_walk(const char *buf, size_t n) { /* STRIDE_REPS passes, n accesses each */
    uint64_t s = 0;
    for (int r = 0; r < STRIDE_REPS; r++)
        for (size_t i = 0; i < n; i++) s += buf[i * STRIDE_STEP];
    return s;
}

static double p_stride(char *buf, size_t size) { /* page-stride walk: TLB-miss proxy */
    size_t n = size / STRIDE_STEP;
    double t0 = now_ns();
    sink = stride_walk(buf, n);
    return (now_ns() - t0) / (STRIDE_REPS * n);
}

static size_t *chain;
static double p_rand(size_t hops) { /* pointer chase over a random cycle: ns per access */
    double t0 = now_ns();
    size_t p = 0;
    for (size_t i = 0; i < hops; i++) p = chain[p];
    sink = p;
    return (now_ns() - t0) / hops;
}

/* MAD (median absolute deviation, in us) of a fixed 100 us sleep; robust to rare long preemptions */
static double p_sleep_jitter(void) {
    double v[100], dev[100];
    for (int i = 0; i < 100; i++) {
        struct timespec ts = {0, 100000};
        double t0 = now_ns();
        nanosleep(&ts, NULL);
        v[i] = (now_ns() - t0) / 1000.0;
    }
    double med = median(v, 100);
    for (int i = 0; i < 100; i++) dev[i] = fabs(v[i] - med);
    return median(dev, 100);
}

/* perf counters over the page-stride walk. cycles is the group leader so cycles, instructions and
 * dTLB misses are counted over exactly the same time slices. */
static int perf_open(uint32_t type, uint64_t config, int group_fd) {
    struct perf_event_attr a;
    memset(&a, 0, sizeof a);
    a.type = type;
    a.size = sizeof a;
    a.config = config;
    a.disabled = group_fd < 0; /* only the leader is gated; members follow it */
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    a.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    return (int)syscall(SYS_perf_event_open, &a, 0, -1, group_fd, 0);
}

static void perf_probe(char *buf, size_t size, double *ipc, double *tlbmiss) {
    *ipc = *tlbmiss = NAN;
    int lead = perf_open(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES, -1);
    if (lead < 0) return;
    int ins = perf_open(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS, lead);
    int tlb = perf_open(PERF_TYPE_HW_CACHE,
                        PERF_COUNT_HW_CACHE_DTLB | (PERF_COUNT_HW_CACHE_OP_READ << 8) |
                            ((uint64_t)PERF_COUNT_HW_CACHE_RESULT_MISS << 16),
                        lead);
    size_t n = size / STRIDE_STEP;
    sink = stride_walk(buf, n); /* untimed warm pass (page tables, caches) */
    ioctl(lead, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
    ioctl(lead, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
    sink = stride_walk(buf, n);
    ioctl(lead, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);

    /* group layout: nr, time_enabled, time_running, then one value per member in open order */
    uint64_t r[3 + 3];
    uint64_t want = 1 + (ins >= 0) + (tlb >= 0);
    ssize_t got = read(lead, r, sizeof r);
    if (got >= (ssize_t)((3 + want) * 8) && r[0] == want && r[1] == r[2]) { /* r[1]!=r[2]: multiplexed */
        size_t k = 1;
        if (ins >= 0) { if (r[3] > 0) *ipc = (double)r[3 + k] / (double)r[3]; k++; }
        if (tlb >= 0) *tlbmiss = (double)r[3 + k] / (double)(STRIDE_REPS * n);
    }
    close(lead);
    if (ins >= 0) close(ins);
    if (tlb >= 0) close(tlb);
}

/* ---- background load ---- */
static volatile pid_t load_pid;

static void on_signal(int sig) { /* parent: never leave the load child behind */
    (void)sig;
    if (load_pid > 0) kill(load_pid, SIGKILL);
    _exit(130);
}

/* Child inherits the parent's CPU affinity (parent pins itself before fork). */
static pid_t start_load(const char *w) {
    if (!strcmp(w, "idle")) return 0;
    pid_t parent = getpid();
    pid_t pid = fork();
    if (pid < 0) { perror("fork"); exit(1); }
    if (pid) return pid;
    signal(SIGINT, SIG_DFL);
    signal(SIGTERM, SIG_DFL);
    prctl(PR_SET_PDEATHSIG, SIGKILL);
    if (getppid() != parent) _exit(0); /* parent already died (getppid()==1 or reaper) */
    int do_cpu = strcmp(w, "mem") != 0, do_mem = strcmp(w, "cpu") != 0;
    char *buf = xmap(BUF_SIZE);
    memset(buf, 1, BUF_SIZE);
    uint64_t s = 0, lcg = 88172645463325252ULL;
    for (;;) {
        double x = 1.0; /* reset every pass: stays ~1.1, never overflows */
        if (do_cpu) for (int i = 0; i < 1000000; i++) x = x * 1.0000001 + 1e-9;
        if (do_mem) /* random-access walk over the whole buffer: defeats prefetch, evicts cache */
            for (int i = 0; i < 1000000; i++) {
                lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
                s += buf[(lcg >> 20) & (BUF_SIZE - 1)];
            }
        sink = s + (uint64_t)x;
    }
}

/* ---- environment metadata ---- */
static void read_line(const char *path, const char *key, char *out, size_t n) {
    snprintf(out, n, "n/a");
    FILE *f = fopen(path, "r");
    if (!f) return;
    char l[512];
    while (fgets(l, sizeof l, f)) {
        char *v = l;
        if (key) {
            if (strncmp(l, key, strlen(key))) continue;
            v = strchr(l, ':');
            if (!v) continue;
            v += 1;
            while (*v == ' ') v++;
        }
        v[strcspn(v, "\r\n")] = 0;
        snprintf(out, n, "%.*s", (int)(n - 1), v); /* explicit cut to the caller's buffer: a longer line is truncated on purpose */
        break;
    }
    fclose(f);
}

static void print_metadata(int cpu, double startup_ms) {
    char model[256], clk[64], thp[64];
    unsigned a = 0, b = 0, c = 0, d = 0;
    struct utsname u;
    read_line("/proc/cpuinfo", "model name", model, sizeof model);
    read_line("/sys/devices/system/clocksource/clocksource0/current_clocksource", NULL, clk, sizeof clk);
    read_line("/sys/kernel/mm/transparent_hugepage/enabled", NULL, thp, sizeof thp);
    int hv = __get_cpuid(1, &a, &b, &c, &d) ? (int)((c >> 31) & 1) : -1;
    if (uname(&u) != 0) snprintf(u.release, sizeof u.release, "n/a");
    long llc = sysconf(_SC_LEVEL3_CACHE_SIZE);
    fprintf(stderr,
            "# cpu_model=\"%s\" hypervisor_bit=%d clocksource=%s thp=\"%s\" pinned_cpu=%d kernel=%s "
            "llc_kb=%ld buf_mb=%lu startup_ms=%.1f\n",
            model, hv, clk, thp, cpu, u.release, llc > 0 ? llc / 1024 : 0L, (unsigned long)(BUF_SIZE / MB),
            startup_ms);
}

/* 1 if the load child has exited (any reason, including already reaped), else 0. Polled once per window. */
static int load_died(pid_t load) {
    if (load <= 0) return 0;
    return waitpid(load, NULL, WNOHANG) != 0;
}

/* ---- one window: all probes once ---- */
struct row {
    double elapsed_ms, cpuid, rdtsc, sc, pf, seq, st, rn, jit, ipc, tlb;
};

static void run_window(char *buf, double scale, struct row *r) {
    int reps = (int)(200 * scale) + 5;
    double t0 = now_ns();
    r->cpuid = p_cpuid(reps);
    r->rdtsc = p_rdtsc();
    r->sc = p_syscall(reps * 10);
    r->pf = p_pagefault(256 + (int)(768 * scale)); /* always >= 256 pages */
    r->seq = p_seq(buf, BUF_SIZE);
    r->st = p_stride(buf, BUF_SIZE);
    r->rn = p_rand((size_t)(200000 * scale) + 10000);
    r->jit = p_sleep_jitter();
    perf_probe(buf, BUF_SIZE, &r->ipc, &r->tlb);
    r->elapsed_ms = (now_ns() - t0) / 1e6;
}

int main(int argc, char **argv) {
    double t_start = now_ns();
    if (argc < 4) { fprintf(stderr, "usage: %s <idle|cpu|mem|mixed> <window_ms> <n_windows>\n"
                                    "  window_ms only scales probe size (not a duration); see elapsed_ms\n", argv[0]); return 2; }
    const char *workload = argv[1];
    if (strcmp(workload, "idle") && strcmp(workload, "cpu") && strcmp(workload, "mem") && strcmp(workload, "mixed")) {
        fprintf(stderr, "unknown workload '%s'\n", workload);
        return 2;
    }
    int window_ms = atoi(argv[2]), n_windows = atoi(argv[3]);
    double scale = window_ms / 100.0; /* probe sizes are tuned for ~100 ms and scaled down */
    if (scale > 1) scale = 1;
    if (scale < 0.01) scale = 0.01;

    /* pin: first allowed CPU that is not 0 when several are allowed (CPU 0 takes most interrupts) */
    cpu_set_t allowed, set;
    if (sched_getaffinity(0, sizeof allowed, &allowed) != 0) { perror("sched_getaffinity"); return 1; }
    int cpu = -1, first = -1;
    for (int i = 0; i < CPU_SETSIZE; i++)
        if (CPU_ISSET(i, &allowed)) {
            if (first < 0) first = i;
            if (i != 0 && cpu < 0) cpu = i;
        }
    if (first < 0) { fprintf(stderr, "no allowed CPU\n"); return 1; }
    if (cpu < 0 || CPU_COUNT(&allowed) < 2) cpu = first;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof set, &set) != 0) { perror("sched_setaffinity"); return 1; }
    prctl(PR_SET_TIMERSLACK, 1); /* 1 ns (0 would restore the 50 us default); inherited by the child */

    char *buf = xmap(BUF_SIZE);
    memset(buf, 1, BUF_SIZE);
    size_t nchain = BUF_SIZE / sizeof(size_t);
    chain = xmap(BUF_SIZE);
    for (size_t i = 0; i < nchain; i++) chain[i] = i;
    srand(12345); /* Sattolo shuffle: a single random cycle (nchain < RAND_MAX) */
    for (size_t i = nchain - 1; i > 0; i--) {
        size_t j = (size_t)rand() % i, t = chain[i];
        chain[i] = chain[j];
        chain[j] = t;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    load_pid = start_load(workload);
    pid_t load = load_pid;

    usleep(500000); /* let the load reach steady state */
    struct row r;
    run_window(buf, scale, &r); /* discarded warm-up pass */
    print_metadata(cpu, (now_ns() - t_start) / 1e6);

    printf("window,workload,elapsed_ms,cpuid_tsc,rdtsc_tsc,syscall_ns,pagefault_ns,seq_ns,stride_ns,rand_ns,sleep_jitter_us,ipc,dtlb_miss\n");
    for (int w = 0; w < n_windows; w++) {
        run_window(buf, scale, &r);
        printf("%d,%s,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%.6g,%.6g,%.6g\n", w, workload, r.elapsed_ms, r.cpuid,
               r.rdtsc, r.sc, r.pf, r.seq, r.st, r.rn, r.jit, r.ipc, r.tlb);
        fflush(stdout);
        if (load_died(load)) { /* a dead load turns 'mixed' into 'idle': never keep measuring silently */
            fprintf(stderr, "# load_dead=1 window=%d\n", w);
            return 3;
        }
    }
    if (load_died(load)) { /* final check; covers a very short run */
        fprintf(stderr, "# load_dead=1 window=%d\n", n_windows);
        return 3;
    }
    if (load > 0) { kill(load, SIGKILL); waitpid(load, NULL, 0); }
    fprintf(stderr, "# load_alive=1\n");
    return 0;
}
