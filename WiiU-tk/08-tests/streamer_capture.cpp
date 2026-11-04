// Loopback stream validator: drives the patched VideoStreamer at 127.0.0.1,
// captures the VSTRM datagrams it emits, and writes them as a classic pcap of
// raw IPv4 records (linktype 101).
//
// Why: Barista's reconstruct-media-capture.py can turn captured VSTRM payloads
// back into Annex-B H.264 by re-adding the slice headers the pad's decoder
// supplies itself. If that reconstruction decodes cleanly with ffmpeg, then our
// encoder + DRH chunking + packetisation are correct end to end - with no
// GamePad and no radio. See research/CODEC-SPEC.md.
//
// Usage: streamer_capture <out.pcap> [frames]
#include <drc/internal/video-streamer.h>
#include <drc/screen.h>
#include <drc/types.h>

#include <arpa/inet.h>
#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

namespace {

const unsigned short kVstrmPort = 50120;
const unsigned short kAstrmPort = 50121;

int MakeReceiver(unsigned short port) {
  const int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (fd < 0) return -1;
  sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
    close(fd);
    return -1;
  }
  return fd;
}

void WriteFileHeader(FILE* f) {
  // Classic pcap, little endian, microsecond timestamps, linktype 101 (raw IP).
  const unsigned int magic = 0xa1b2c3d4;
  const unsigned short major = 2, minor = 4;
  const unsigned int snaplen = 65535;
  const unsigned int linktype = 101;
  fwrite(&magic, 4, 1, f);
  fwrite(&major, 2, 1, f);
  fwrite(&minor, 2, 1, f);
  // zigzag: the on-disk magic is 0xa1b2c3d4 in host order for LE files
  const int zero = 0;
  fwrite(&zero, 4, 1, f);
  fwrite(&zero, 4, 1, f);
  fwrite(&snaplen, 4, 1, f);
  fwrite(&linktype, 4, 1, f);
}

// Minimal IPv4 + UDP header around the payload so the analyzer can parse it.
void WritePacket(FILE* f, unsigned short dst_port, const unsigned char* payload,
                 size_t len) {
  const size_t ip_len = 20 + 8 + len;
  std::vector<unsigned char> pkt(ip_len, 0);

  pkt[0] = 0x45;                     // IPv4, IHL 5
  pkt[1] = 0x00;                     // DSCP/ECN
  pkt[2] = (unsigned char)(ip_len >> 8);
  pkt[3] = (unsigned char)(ip_len & 0xFF);
  pkt[8] = 64;                       // TTL
  pkt[9] = 17;                       // UDP
  // The DRC network addresses: Barista's analyzer filters on these, and the
  // real pad lives at 192.168.1.11 behind an AP at 192.168.1.10. The transport
  // here is loopback; only the synthetic headers claim otherwise.
  pkt[12] = 192; pkt[13] = 168; pkt[14] = 1; pkt[15] = 10;   // host (AP)
  pkt[16] = 192; pkt[17] = 168; pkt[18] = 1; pkt[19] = 11;   // GamePad

  const size_t udp_off = 20;
  pkt[udp_off + 0] = (unsigned char)(50020 >> 8);
  pkt[udp_off + 1] = (unsigned char)(50020 & 0xFF);
  pkt[udp_off + 2] = (unsigned char)(dst_port >> 8);
  pkt[udp_off + 3] = (unsigned char)(dst_port & 0xFF);
  const size_t udp_len = 8 + len;
  pkt[udp_off + 4] = (unsigned char)(udp_len >> 8);
  pkt[udp_off + 5] = (unsigned char)(udp_len & 0xFF);
  memcpy(pkt.data() + udp_off + 8, payload, len);

  const auto now = std::chrono::system_clock::now().time_since_epoch();
  const unsigned int sec = (unsigned int)std::chrono::duration_cast<
      std::chrono::seconds>(now).count();
  const unsigned int usec = (unsigned int)(
      std::chrono::duration_cast<std::chrono::microseconds>(now).count() %
      1000000);
  const unsigned int size = (unsigned int)pkt.size();
  fwrite(&sec, 4, 1, f);
  fwrite(&usec, 4, 1, f);
  fwrite(&size, 4, 1, f);
  fwrite(&size, 4, 1, f);
  fwrite(pkt.data(), 1, pkt.size(), f);
}

}  // namespace

int main(int argc, char** argv) {
  const char* out = (argc > 1) ? argv[1] : "/tmp/drc-loopback.pcap";
  const int frames = (argc > 2) ? atoi(argv[2]) : 120;

  const int vfd = MakeReceiver(kVstrmPort);
  const int afd = MakeReceiver(kAstrmPort);
  if (vfd < 0 || afd < 0) {
    printf("[capture] FAIL: cannot bind loopback 50120/50121\n");
    return 1;
  }

  FILE* pcap = fopen(out, "wb");
  if (!pcap) {
    printf("[capture] FAIL: cannot open %s\n", out);
    return 1;
  }
  WriteFileHeader(pcap);

  std::atomic<bool> stop{false};
  std::atomic<unsigned long> vstrm_pkts{0}, astrm_pkts{0};

  std::thread reader([&] {
    std::vector<unsigned char> buf(4096);
    // poll() on both sockets: a blocking recv per socket would throttle the
    // reader to a handful of packets per timeout and silently lose the stream.
    pollfd fds[2];
    fds[0].fd = vfd; fds[0].events = POLLIN; fds[0].revents = 0;
    fds[1].fd = afd; fds[1].events = POLLIN; fds[1].revents = 0;
    while (!stop.load()) {
      const int r = poll(fds, 2, 50);
      if (r <= 0) continue;
      if (fds[0].revents & POLLIN) {
        while (true) {
          const ssize_t n = recv(vfd, buf.data(), buf.size(), MSG_DONTWAIT);
          if (n <= 0) break;
          WritePacket(pcap, kVstrmPort, buf.data(), (size_t)n);
          vstrm_pkts++;
        }
      }
      if (fds[1].revents & POLLIN) {
        while (true) {
          const ssize_t m = recv(afd, buf.data(), buf.size(), MSG_DONTWAIT);
          if (m <= 0) break;
          WritePacket(pcap, kAstrmPort, buf.data(), (size_t)m);
          astrm_pkts++;
        }
      }
    }
  });

  printf("[capture] streaming %d frames to 127.0.0.1:%u\n", frames, kVstrmPort);
  drc::VideoStreamer streamer("127.0.0.1:50120", "127.0.0.1:50121");
  if (!streamer.Start()) {
    printf("[capture] FAIL: streamer did not start\n");
    stop = true;
    reader.join();
    fclose(pcap);
    return 1;
  }

  const int kW = drc::kScreenWidth, kH = drc::kScreenHeight;
  const size_t kBytes = (size_t)kW * kH * 3 / 2;
  std::vector<drc::byte> frame(kBytes);
  for (int n = 0; n < frames; ++n) {
    // Textured content so frames are non-trivial (a flat field encodes to
    // tens of bytes and would not exercise splitting).
    for (int j = 0; j < kH; ++j) {
      for (int i = 0; i < kW; ++i) {
        const int checker = ((i >> 3) ^ (j >> 3) ^ (n >> 2)) & 1;
        frame[(size_t)j * kW + i] =
            (drc::byte)(64 + ((i * 3 + j * 5 + n * 11) & 0x7F) + checker * 40);
      }
    }
    for (size_t k = (size_t)kW * kH; k < kBytes; ++k) frame[k] = 128;
    std::vector<drc::byte> copy = frame;
    streamer.PushFrame(&copy);
    std::this_thread::sleep_for(std::chrono::microseconds(16683));
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(50));
  streamer.Stop();
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  stop = true;
  reader.join();
  fclose(pcap);
  close(vfd);
  close(afd);

  printf("[capture] wrote %s: %lu vstrm, %lu astrm datagrams, %llu paced, "
         "%llu superseded\n",
         out, vstrm_pkts.load(), astrm_pkts.load(),
         (unsigned long long)streamer.paced_packets(),
         (unsigned long long)streamer.dropped_jobs());
  return vstrm_pkts.load() > 0 ? 0 : 1;
}
