// Streamer smoke test: exercises the patched VideoStreamer's thread lifecycle
// with no GamePad and no radio.
//
// The patch (research/CODEC-SPEC.md 3.5) moved encoding and sending onto a
// separate thread fed by a single-slot mailbox. The failure modes that matter
// without hardware are: a deadlock on Stop(), a crash when frames arrive faster
// than they are sent, and unbounded memory growth.
//
// UdpClient only creates a socket and parses the destination, so sends to an
// unreachable 192.168.1.11 are harmless here.
//
// Build: see tests/run-streamer-smoke.sh
#include <drc/internal/video-streamer.h>
#include <drc/screen.h>
#include <drc/types.h>

#include <chrono>
#include <cstdio>
#include <thread>
#include <vector>

int main() {
  const int kW = drc::kScreenWidth;
  const int kH = drc::kScreenHeight;
  const size_t kFrameBytes = (size_t)kW * kH * 3 / 2;

  printf("[smoke] constructing VideoStreamer at 192.168.1.11 (unreachable)\n");
  drc::VideoStreamer streamer("192.168.1.11:50120", "192.168.1.11:50121");

  if (!streamer.Start()) {
    printf("[smoke] FAIL: Start() returned false\n");
    return 1;
  }
  printf("[smoke] started; pushing 30 frames at ~60 Hz\n");

  std::vector<drc::byte> frame(kFrameBytes);
  const auto t0 = std::chrono::steady_clock::now();
  for (int n = 0; n < 30; ++n) {
    for (size_t i = 0; i < kFrameBytes; ++i) {
      frame[i] = (drc::byte)((i + n * 7) & 0xFF);
    }
    std::vector<drc::byte> copy = frame;  // PushFrame moves its argument
    streamer.PushFrame(&copy);
    std::this_thread::sleep_for(std::chrono::microseconds(16683));
  }
  const auto pushed = std::chrono::steady_clock::now();

  // Stop must return promptly: that is the deadlock check.
  printf("[smoke] stopping\n");
  streamer.Stop();
  const auto stopped = std::chrono::steady_clock::now();

  const auto push_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(pushed - t0).count();
  const auto stop_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(stopped - pushed)
          .count();

  printf("[smoke] pushed 30 frames in %lld ms (expected ~500)\n",
         (long long)push_ms);
  printf("[smoke] packets paced: %llu, jobs superseded: %llu\n",
         (unsigned long long)streamer.paced_packets(),
         (unsigned long long)streamer.dropped_jobs());
  printf("[smoke] Stop() took %lld ms (expected < 1000)\n", (long long)stop_ms);

  bool ok = true;
  if (stop_ms > 1000) {
    printf("[smoke] FAIL: Stop() blocked - sender thread did not exit\n");
    ok = false;
  }
  if (streamer.paced_packets() == 0) {
    printf("[smoke] FAIL: nothing was packetised - sender never ran\n");
    ok = false;
  }
  if (push_ms < 300 || push_ms > 3000) {
    printf("[smoke] FAIL: producer cadence implausible\n");
    ok = false;
  }
  printf("[smoke] %s\n", ok ? "PASS" : "FAIL");
  return ok ? 0 : 1;
}
