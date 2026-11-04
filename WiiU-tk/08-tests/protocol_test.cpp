// Round-trip tests for libdrc's DRC wire-format packet classes.
//
// The video/command headers are hand-packed bitfields that are parsed both by us
// (on the way out) and by the GamePad. An asymmetry between Set* and the accessors
// would silently corrupt every frame, so serialise -> parse -> compare is worth
// asserting without any hardware in the loop.
#include <cstdio>
#include <cstring>
#include <vector>

#include <drc/internal/vstrm-packet.h>
#include <drc/internal/cmd-packet.h>
#include <drc/video-frame-rate.h>

static int failures = 0;
#define CHECK(cond, msg)                                                      \
  do {                                                                        \
    if (!(cond)) { printf("  FAIL %s\n", msg); ++failures; }                  \
    else { printf("  ok   %s\n", msg); }                                      \
  } while (0)

static std::vector<drc::byte> reparse(const drc::byte* p, size_t n) {
  return std::vector<drc::byte>(p, p + n);
}

static void test_vstrm(size_t payload_len) {
  std::vector<drc::byte> payload(payload_len);
  for (size_t i = 0; i < payload_len; ++i) payload[i] = (drc::byte)(i * 7 + 3);

  // SeqId is a 10-bit field (2 bits in pkt_[0] + pkt_[1]); the length is 11 bits.
  // Values wider than that are truncated by design, so use an in-range seqid here.
  const drc::u16 seqid = 0x02AB;

  drc::VstrmPacket out;
  out.SetSeqId(seqid);
  out.SetTimestamp(0xDEADBEEF);
  out.SetInitFlag(true);
  out.SetFrameBeginFlag(true);
  out.SetChunkEndFlag(false);
  out.SetFrameEndFlag(true);
  out.SetIdrFlag(true);
  out.SetFrameRate(drc::VideoFrameRate::k59_94Hz);
  if (payload_len) out.SetPayload(payload.data(), payload.size());

  printf("vstrm payload=%zu: size=%zu\n", payload_len, out.GetSize());
  CHECK(out.GetSize() == drc::kVstrmHeaderSize + payload_len,
        "GetSize == header + payload");

  drc::VstrmPacket in(reparse(out.GetBytes(), out.GetSize()));
  CHECK(in.SeqId() == seqid, "seqid survives");
  CHECK(in.Timestamp() == 0xDEADBEEF, "timestamp survives");
  CHECK(in.InitFlag() == true, "init flag survives");
  CHECK(in.FrameBeginFlag() == true, "frame-begin flag survives");
  CHECK(in.ChunkEndFlag() == false, "chunk-end flag survives (false)");
  CHECK(in.FrameEndFlag() == true, "frame-end flag survives");
  CHECK(in.IdrFlag() == true, "idr flag survives");
  CHECK(in.FrameRate() == drc::VideoFrameRate::k59_94Hz, "frame rate survives");
  CHECK(in.PayloadSize() == payload_len, "payload size survives");
  if (payload_len)
    CHECK(memcmp(in.Payload(), payload.data(), payload_len) == 0,
          "payload bytes survive");
}

static void test_cmd(size_t payload_len) {
  std::vector<drc::byte> payload(payload_len);
  for (size_t i = 0; i < payload_len; ++i) payload[i] = (drc::byte)(0xA0 + i);

  drc::CmdPacket out;
  out.SetPacketType(drc::CmdPacketType::kQuery);
  out.SetQueryType(drc::CmdQueryType::kTimeCommand);
  out.SetSeqId(0x0042);
  if (payload_len) out.SetPayload(payload.data(), payload.size());

  printf("cmd payload=%zu: size=%zu\n", payload_len, out.GetSize());
  CHECK(out.GetSize() == drc::kCmdHeaderSize + payload_len,
        "GetSize == 8-byte header + payload");

  drc::CmdPacket in(reparse(out.GetBytes(), out.GetSize()));
  CHECK(in.PacketType() == drc::CmdPacketType::kQuery, "packet type survives");
  CHECK(in.QueryType() == drc::CmdQueryType::kTimeCommand, "query type survives");
  CHECK(in.SeqId() == 0x0042, "seqid survives");
  CHECK(in.PayloadSize() == payload_len, "payload size survives");
}

static void test_field_widths() {
  // Document the wire field widths so nobody "fixes" them into a 16-bit counter.
  drc::VstrmPacket p;
  p.SetSeqId(0xFFFF);
  printf("field widths: SetSeqId(0xFFFF) -> SeqId()=0x%03X\n", p.SeqId());
  CHECK(p.SeqId() == 0x3FF, "seqid is truncated to 10 bits");

  std::vector<drc::byte> big(drc::kMaxVstrmPayloadSize, 0x5A);
  p.SetPayload(big.data(), big.size());
  CHECK(p.PayloadSize() == drc::kMaxVstrmPayloadSize, "max payload fits");
  CHECK(drc::kMaxVstrmPayloadSize <= 0x7FF,
        "max payload fits the 11-bit length field");
}

int main() {
  printf("[protocol] vstrm (video stream) header round-trip\n");
  test_vstrm(0);
  test_vstrm(1);
  test_vstrm(100);
  test_vstrm(drc::kMaxVstrmPayloadSize);

  printf("\n[protocol] wire field widths\n");
  test_field_widths();

  printf("\n[protocol] cmd packet round-trip\n");
  test_cmd(0);
  test_cmd(4);
  test_cmd(64);

  printf("\n[protocol] %s (%d failures)\n",
         failures ? "FAIL" : "PASS", failures);
  return failures ? 1 : 0;
}
