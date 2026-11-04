// Hardware-free validation of the GamePad H.264 encoder path.
//
//   mode "drh"  : drives libdrc's drc::H264Encoder exactly as the streamer does and
//                 checks the DRH chunking contract (5 macroblock-row chunks/frame).
//   mode "file" : re-encodes with libdrc's exact x264 parameters (854x480, I420,
//                 CQP 32, main profile, cabac, b_drh_mode=1) but with repeat_headers
//                 so the result is a standalone stream that ffprobe can verify.
//
// This proves the patched x264 in drc-x264 produces valid video at the GamePad's
// settings, which is pc2drc's "known major x264 encoder issue" risk area.
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <vector>

#include <drc/internal/h264-encoder.h>
#include <drc/internal/tsf.h>
#include <drc/screen.h>
#include <drc/types.h>
#include <unistd.h>

// Verifies the TSF clock source: the patched-mac80211 sysfs node, or the
// DRC_SYNTHETIC_TSF=1 monotonic fallback for radios without get_tsf().
static int mode_tsf() {
  drc::u64 a = 0, b = 0;
  int r1 = drc::GetTsf(&a);
  usleep(250000);
  int r2 = drc::GetTsf(&b);
  printf("[tsf] GetTsf -> %d then %d\n", r1, r2);
  if (r1 != 0 || r2 != 0) {
    printf("[tsf] FAIL: no clock source (load the patched mac80211 or set "
           "DRC_SYNTHETIC_TSF=1)\n");
    return 1;
  }
  long long delta = (long long)(b - a);
  printf("[tsf] %llu -> %llu  (delta %lld us over ~250000 us)\n",
         (unsigned long long)a, (unsigned long long)b, delta);
  // A 250 ms sleep must show up as ~250000 us of TSF.
  if (delta > 100000 && delta < 600000) {
    printf("[tsf] PASS: clock is advancing at ~1 us/us\n");
    return 0;
  }
  printf("[tsf] FAIL: delta implausible\n");
  return 1;
}

static void fill_i420(std::vector<drc::byte>& f, int frame) {
  const int w = drc::kScreenWidth, h = drc::kScreenHeight;
  drc::byte* y = f.data();
  drc::byte* u = y + w * h;
  drc::byte* v = u + (w * h) / 4;
  for (int j = 0; j < h; ++j)
    for (int i = 0; i < w; ++i)
      y[j * w + i] = (drc::byte)((i + j + frame * 7) & 0xFF);
  for (int j = 0; j < h / 2; ++j)
    for (int i = 0; i < w / 2; ++i) {
      u[j * (w / 2) + i] = (drc::byte)(64 + ((i + frame) & 0x7F));
      v[j * (w / 2) + i] = (drc::byte)(192 - ((j + frame) & 0x7F));
    }
}

static int mode_drh() {
  printf("[drh] driving drc::H264Encoder at %ux%u\n",
         drc::kScreenWidth, drc::kScreenHeight);
  drc::H264Encoder enc;
  std::vector<drc::byte> frame(drc::kScreenWidth * drc::kScreenHeight * 3 / 2);

  int bad = 0;
  for (int n = 0; n < 12; ++n) {
    fill_i420(frame, n);
    const drc::H264ChunkArray& chunks = enc.Encode(frame, n == 0);
    int nonempty = 0; size_t total = 0; int minc = 1 << 30, maxc = 0;
    for (const auto& c : chunks) {
      size_t len = std::get<1>(c);
      if (std::get<0>(c) && len) { ++nonempty; total += len;
        if ((int)len < minc) minc = (int)len;
        if ((int)len > maxc) maxc = (int)len; }
    }
    printf("  frame %2d: %d/5 chunks, %zu bytes total (chunk %d..%d B)\n",
           n, nonempty, total, minc, maxc);
    if (nonempty != drc::kH264ChunksPerFrame) ++bad;
  }
  printf("[drh] %s: %d/%d frames had exactly %d chunks\n",
         bad ? "FAIL" : "PASS", 12 - bad, 12, drc::kH264ChunksPerFrame);
  return bad ? 1 : 0;
}

// DRC chunking only happens through the nalu_process callback, so collect the NALs.
static std::vector<std::vector<drc::byte>> g_nals;
static void collect_nal(x264_t*, x264_nal_t* nal, void*) {
  if (nal->i_type == NAL_SEI) return;
  g_nals.emplace_back(nal->p_payload, nal->p_payload + nal->i_payload);
}

static void base_params(x264_param_t& p, int drh) {
  x264_param_default_preset(&p, "ultrafast", "zerolatency");
  p.i_width = drc::kScreenWidth;
  p.i_height = drc::kScreenHeight;
  p.analyse.inter &= ~X264_ANALYSE_PSUB16x16;
  p.i_scenecut_threshold = -1;
  p.i_csp = X264_CSP_I420;
  p.b_cabac = 1;
  p.b_interlaced = 0;
  p.i_bframe = 0;
  p.i_bframe_pyramid = 0;
  p.i_frame_reference = 1;
  p.b_constrained_intra = 1;
  p.analyse.i_weighted_pred = 0;
  p.analyse.b_weighted_bipred = 0;
  p.analyse.b_transform_8x8 = 0;
  p.analyse.i_chroma_qp_offset = 0;
  p.rc.i_rc_method = X264_RC_CQP;
  p.rc.i_qp_constant = p.rc.i_qp_min = p.rc.i_qp_max = 32;
  p.rc.f_ip_factor = 1.0;
  p.b_aud = 0;
  p.b_drh_mode = drh;
  p.i_threads = 1;
  p.b_sliced_threads = 0;
  p.i_slice_count = 1;
  p.i_log_level = X264_LOG_NONE;
  x264_param_apply_profile(&p, "main");
}

static void feed(x264_t* enc, x264_picture_t& in, std::vector<drc::byte>& frame,
                 int n) {
  static const int w = drc::kScreenWidth, h = drc::kScreenHeight;
  x264_picture_init(&in);
  in.img.i_csp = X264_CSP_I420;
  in.img.i_plane = 3;
  in.img.i_stride[0] = w;
  in.img.i_stride[1] = w / 2;
  in.img.i_stride[2] = w / 2;
  fill_i420(frame, n);
  in.img.plane[0] = frame.data();
  in.img.plane[1] = frame.data() + w * h;
  in.img.plane[2] = in.img.plane[1] + (w * h) / 4;
  in.i_type = n == 0 ? X264_TYPE_IDR : X264_TYPE_P;
}

static int mode_file(const char* out) {
  std::vector<drc::byte> frame(drc::kScreenWidth * drc::kScreenHeight * 3 / 2);

  // Pass 1: normal encode just to harvest SPS/PPS for these exact settings.
  std::vector<drc::byte> sps, pps;
  {
    x264_param_t p; base_params(p, /*drh=*/0);
    p.b_repeat_headers = 1;
    x264_t* e = x264_encoder_open(&p);
    if (!e) { printf("[file] encoder open failed\n"); return 1; }
    x264_picture_t in, outp; feed(e, in, frame, 0);
    x264_nal_t* nals = nullptr; int nc = 0;
    x264_encoder_encode(e, &nals, &nc, &in, &outp);
    for (int i = 0; i < nc; ++i) {
      if (nals[i].i_type == NAL_SPS) sps.assign(nals[i].p_payload,
                                                nals[i].p_payload + nals[i].i_payload);
      if (nals[i].i_type == NAL_PPS) pps.assign(nals[i].p_payload,
                                                nals[i].p_payload + nals[i].i_payload);
    }
    x264_encoder_close(e);
  }
  printf("[file] SPS %zu bytes, PPS %zu bytes\n", sps.size(), pps.size());
  if (sps.empty() || pps.empty()) { printf("[file] no SPS/PPS\n"); return 1; }

  // Pass 2: DRH-mode encode through the callback, emitted as Annex-B slices.
  x264_param_t p; base_params(p, /*drh=*/1);
  p.b_repeat_headers = 0;
  p.nalu_process = collect_nal;
  x264_t* e = x264_encoder_open(&p);
  if (!e) { printf("[file] drh encoder open failed\n"); return 1; }

  FILE* f = fopen(out, "wb");
  if (!f) { printf("[file] cannot write %s\n", out); return 1; }
  const drc::byte sc[4] = {0, 0, 0, 1};
  size_t written = 0, slices = 0;

  for (int n = 0; n < 60; ++n) {
    g_nals.clear();
    x264_picture_t in, outp; feed(e, in, frame, n);
    x264_nal_t* nals = nullptr; int nc = 0;
    if (x264_encoder_encode(e, &nals, &nc, &in, &outp) < 0) {
      printf("[file] encode failed at frame %d\n", n); break;
    }
    if (n == 0) {
      fwrite(sc, 1, 4, f); fwrite(sps.data(), 1, sps.size(), f); written += 4 + sps.size();
      fwrite(sc, 1, 4, f); fwrite(pps.data(), 1, pps.size(), f); written += 4 + pps.size();
    }
    for (const auto& nal : g_nals) {
      fwrite(sc, 1, 4, f); fwrite(nal.data(), 1, nal.size(), f);
      written += 4 + nal.size(); ++slices;
    }
  }
  fclose(f);
  x264_encoder_close(e);
  printf("[file] wrote %s: %zu bytes, %zu slice NALs over 60 frames (%zu/frame)\n",
         out, written, slices, slices / 60);
  return 0;
}

int main(int argc, char** argv) {
  if (argc < 2) { printf("usage: %s drh|file [out.h264]\n", argv[0]); return 2; }
  if (!strcmp(argv[1], "drh")) return mode_drh();
  if (!strcmp(argv[1], "tsf")) return mode_tsf();
  if (!strcmp(argv[1], "file")) return mode_file(argc > 2 ? argv[2] : "/tmp/drc-test.h264");
  printf("unknown mode\n");
  return 2;
}
