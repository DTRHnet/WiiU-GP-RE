/* encode_dump - encode frames with libdrc's encoder settings and write an
 * Annex-B H.264 elementary stream.
 *
 * Purpose: the GamePad ignores in-band parameter sets and decodes against a
 * HARDCODED SPS/PPS. So the pad's effective input is:
 *      pad SPS  (00 00 00 01 67 64 00 20 ac 2b 40 6c 1e f3 68)
 *      pad PPS  (00 00 00 01 68 ee 06 0c e8)
 *   ++  our slice NAL units
 * We can therefore prove pad-compatibility offline: prepend those exact bytes
 * and try to decode with ffmpeg. A parameter mismatch (e.g. frame_num width)
 * makes the decoder fail immediately.
 *
 * b_drh_mode is DISABLED here: it is libdrc's macroblock-row delivery format,
 * not a bitstream change, and it suppresses normal NAL output.
 *
 * build: gcc -O2 -I<drc-x264> encode_dump.c <libx264.a> -lm -lpthread -o encode_dump
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "x264.h"

static void write_annexb(FILE* f, x264_nal_t* nals, int n) {
  for (int i = 0; i < n; i++) {
    if (nals[i].i_payload > 0) fwrite(nals[i].p_payload, 1, nals[i].i_payload, f);
  }
}

int main(int argc, char** argv) {
  const char* preset = argc > 1 ? argv[1] : "ultrafast";
  const char* outpath = argc > 2 ? argv[2] : "/tmp/live.h264";
  int nframes = argc > 3 ? atoi(argv[3]) : 90;
  int width = 854, height = 480;

  x264_param_t param;
  x264_param_default_preset(&param, preset, "zerolatency");
  param.i_width = width;
  param.i_height = height;
  param.analyse.inter &= ~X264_ANALYSE_PSUB16x16;
  /* mirror libdrc: intra-refresh with keyint 10..30 */
  param.i_keyint_min = 10;
  param.i_keyint_max = 30;
  param.i_scenecut_threshold = -1;
  param.i_csp = X264_CSP_I420;
  param.b_cabac = 1;
  param.b_interlaced = 0;
  param.i_bframe = 0;
  param.i_bframe_pyramid = 0;
  param.i_frame_reference = 1;
  param.b_constrained_intra = 1;
  param.b_intra_refresh = 1;
  param.analyse.i_weighted_pred = 0;
  param.analyse.b_weighted_bipred = 0;
  param.analyse.b_transform_8x8 = 0;
  param.analyse.i_chroma_qp_offset = 0;
  param.rc.i_rc_method = X264_RC_CQP;
  param.rc.i_qp_constant = param.rc.i_qp_min = param.rc.i_qp_max = 32;
  param.rc.f_ip_factor = 1.0;
  param.b_repeat_headers = 0;
  param.b_aud = 0;
  param.b_drh_mode = 0;   /* normal NAL output for decodability testing */
  param.i_threads = 1;
  param.b_sliced_threads = 0;
  param.i_slice_count = 1;
  param.b_deblocking_filter = 1;
  param.i_log_level = X264_LOG_NONE;
  x264_param_apply_profile(&param, "high");

  x264_t* enc = x264_encoder_open(&param);
  if (!enc) { fprintf(stderr, "open failed\n"); return 1; }

  FILE* f = fopen(outpath, "wb");
  if (!f) { fprintf(stderr, "cannot write %s\n", outpath); return 1; }

  x264_nal_t* nals; int nnals;
  x264_encoder_headers(enc, &nals, &nnals);   /* deliberately NOT written */

  x264_picture_t pic_in, pic_out;
  x264_picture_alloc(&pic_in, X264_CSP_I420, width, height);

  for (int fr = 0; fr < nframes; fr++) {
    /* moving-content test pattern so inter prediction actually gets used */
    for (int y = 0; y < height; y++) {
      uint8_t* row = pic_in.img.plane[0] + y * pic_in.img.i_stride[0];
      for (int x = 0; x < width; x++) row[x] = (uint8_t)((x + fr * 3) & 0xFF);
    }
    for (int y = 0; y < height / 2; y++) {
      uint8_t* u = pic_in.img.plane[1] + y * pic_in.img.i_stride[1];
      uint8_t* v = pic_in.img.plane[2] + y * pic_in.img.i_stride[2];
      for (int x = 0; x < width / 2; x++) { u[x] = 128; v[x] = (uint8_t)((fr * 2) & 0xFF); }
    }
    pic_in.i_type = fr == 0 ? X264_TYPE_IDR : X264_TYPE_AUTO;
    pic_in.i_pts = fr;
    int size = x264_encoder_encode(enc, &nals, &nnals, &pic_in, &pic_out);
    if (size < 0) { fprintf(stderr, "encode failed at frame %d\n", fr); return 1; }
    write_annexb(f, nals, nnals);
  }
  /* flush */
  while (x264_encoder_delayed_frames(enc)) {
    int size = x264_encoder_encode(enc, &nals, &nnals, NULL, &pic_out);
    if (size <= 0) break;
    write_annexb(f, nals, nnals);
  }
  fclose(f);
  x264_picture_clean(&pic_in);
  x264_encoder_close(enc);
  printf("wrote %s (%d frames, %s)\n", outpath, nframes, preset);
  return 0;
}
