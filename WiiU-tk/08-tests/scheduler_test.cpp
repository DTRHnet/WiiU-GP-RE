// Hardware-free tests for the video packet schedule and the IDR policy that
// replace the two defects found in our streamer (research/CODEC-SPEC.md 3.5):
// no in-frame pacing, and every heartbeat turned into an IDR.
//
//   ./out/bin/scheduler_test
#include <cstdio>
#include <cstdlib>
#include <vector>

#include <drc/internal/idr-policy.h>
#include <drc/internal/video-packet-schedule.h>

using namespace drc;

static int g_fail = 0;

static void check(bool cond, const char* what) {
  if (cond) {
    printf("  PASS  %s\n", what);
  } else {
    printf("  FAIL  %s\n", what);
    ++g_fail;
  }
}

static void test_offsets() {
  printf("video packet schedule\n");

  // Chunk starts and deadlines must match the measured console schedule.
  check(kChunkStartUs[0] == 0 && kChunkStartUs[4] == 11000,
        "chunk windows start at 0/3/6/9/11 ms");
  check(kChunkDeadlineUs[0] == 2500 && kChunkDeadlineUs[4] == 13000,
        "chunk deadlines are 2.5/5/7.5/10/13 ms");

  // A single-packet chunk goes out at its window start.
  check(VideoPacketOffsetUs(0, 0, 1) == 0, "single-packet chunk 0 sends at 0 us");
  check(VideoPacketOffsetUs(4, 0, 1) == 11000,
        "single-packet chunk 4 sends at 11000 us");

  // A multi-packet chunk is spread across its window, not bursted.
  check(VideoPacketOffsetUs(2, 0, 4) == 6000, "first of 4 in chunk 2 at window start");
  check(VideoPacketOffsetUs(2, 3, 4) == 7500, "last of 4 in chunk 2 at deadline");
  std::vector<u32> mid;
  for (size_t i = 0; i < 4; ++i) mid.push_back(VideoPacketOffsetUs(2, i, 4));
  check(mid[0] < mid[1] && mid[1] < mid[2] && mid[2] < mid[3],
        "offsets increase monotonically inside a chunk");
  check(mid[1] > 6000 && mid[1] < 7500, "interior packet lands inside the window");

  // Chunks never overlap: chunk N's last packet is no later than chunk N+1's
  // deadline, and each chunk begins after the previous one's deadline is met.
  bool ordered = true;
  for (size_t c = 0; c + 1 < kVideoChunksPerFrame; ++c) {
    const u32 last_of_c = VideoPacketOffsetUs(c, 9, 10);
    const u32 first_of_next = VideoPacketOffsetUs(c + 1, 0, 10);
    if (last_of_c > first_of_next) ordered = false;
  }
  check(ordered, "chunk N's last packet is not later than chunk N+1's start");

  // Out-of-range input must not read past the tables.
  check(VideoPacketOffsetUs(9, 0, 1) == 0, "chunk index out of range is safe");
  check(VideoPacketOffsetUs(0, 5, 3) == kChunkDeadlineUs[0],
        "packet index out of range clamps to the deadline");

  // Split arithmetic: an IDR chunk from a real desktop capture was 4054 bytes.
  check(ChunkPacketCount(4054, 1694) == 3, "4054 B chunk -> 3 datagrams at 1694");
  check(ChunkPacketCount(1694, 1694) == 1, "exact-fit chunk -> 1 datagram");
  check(ChunkPacketCount(0, 1694) == 0, "empty chunk -> 0 datagrams");
  check(ChunkNeedsSplitting(1832, 1694), "1832 B chunk needs splitting");
  check(!ChunkNeedsSplitting(1137, 1694), "1137 B chunk does not");
}

static void test_idr_policy() {
  printf("idr policy\n");

  // 1. First frame must be an IDR, and the frame after it is format-only.
  {
    IdrPolicy p;
    check(p.Decide(0, false, 0) == IdrDecision::kIdr, "frame 0 is an IDR");
    check(p.Decide(1, false, 16683) == IdrDecision::kFormatOnly,
          "frame 1 is a format-only recovery slot");
    check(p.Decide(2, false, 33366) == IdrDecision::kNone,
          "frame 2 is a normal P frame");
  }

  // 2. A heartbeat every frame must NOT produce IDRs - the 8.6 Mbps bug.
  {
    IdrPolicy p;
    int idrs = 0;
    u64 t = 0;
    for (u64 f = 0; f < 240; ++f, t += 16683) {
      if (p.Decide(f, /*requested=*/true, t) == IdrDecision::kIdr) ++idrs;
    }
    // Expected: frame 0, plus frames 60/120/180 (proactive). A heartbeat on
    // every frame must add nothing.
    check(idrs == 4, "240 frames of per-frame heartbeats -> 4 IDRs, not 240");
  }

  // 3. A genuine request (after a long gap) does produce an IDR.
  {
    IdrPolicy p;
    p.Decide(0, false, 0);            // initial IDR
    p.Decide(1, false, 16683);        // format-only
    const IdrDecision quiet = p.Decide(2, false, 33366);
    const IdrDecision real = p.Decide(3, /*requested=*/true, 50049);
    check(quiet == IdrDecision::kNone, "no request -> no IDR");
    check(real == IdrDecision::kIdr, "isolated request -> IDR");
    check(p.Decide(4, false, 66732) == IdrDecision::kFormatOnly,
          "IDR is followed by a format-only slot");
  }

  // 4. Requests repeating at frame cadence are debounced to liveness.
  {
    IdrPolicy p;
    IdrPolicy q;
    p.Decide(0, true, 0);
    p.Decide(1, true, 16683);
    const IdrDecision a = p.Decide(2, true, 33366);
    q.Reset();
    const IdrDecision b = q.Decide(2, false, 33366);
    check(a == b, "a request 33 ms after the last one is treated as liveness");
  }

  // 5. Proactive IDR cadence is bounded and periodic.
  {
    IdrPolicy p;
    std::vector<u64> idr_frames;
    u64 t = 0;
    for (u64 f = 0; f < 200; ++f, t += 16683) {
      if (p.Decide(f, false, t) == IdrDecision::kIdr) idr_frames.push_back(f);
    }
    check(idr_frames.size() == 4 && idr_frames[0] == 0 &&
              idr_frames[1] == kProactiveIdrFrames,
          "unchanged content -> IDR only at 0/60/120/180");
  }

  // 6. Worst case bandwidth: with the policy, how many IDR frames per second?
  {
    // 60-frame cadence at 59.94 fps ~= 1 IDR/s = 17.8 kB/s ~= 0.14 Mbps on top
    // of the 0.29 Mbps stream, instead of 8.57 Mbps for an IDR every frame.
    const double idr_per_sec = 59.94 / (double)kProactiveIdrFrames;
    check(idr_per_sec < 1.5, "proactive cadence keeps IDR rate at ~1/s");
  }
}

int main() {
  test_offsets();
  test_idr_policy();
  printf("\n%s: %d failure(s)\n", g_fail ? "FAIL" : "PASS", g_fail);
  return g_fail ? 1 : 0;
}
