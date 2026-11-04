/* sps_probe - encode one 854x480 frame with libdrc's encoder parameters and
 * dump the SPS/PPS that our x264 actually emits, so they can be compared
 * byte-for-byte against the GamePad's hardcoded parameter sets:
 *     SPS 67 64 00 20 ac 2b 40 6c 1e f3 68
 *     PPS 68 ee 06 0c e8
 * The pad ignores in-band parameter sets, so byte-identity here is the
 * practical proof that it can parse our slice headers.
 *
 * build: gcc -O2 -I<drc-x264> sps_probe.c <drc-x264>/libx264.a -lm -o sps_probe
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "x264.h"

int main(int argc, char** argv) {
  const char* preset = argc > 1 ? argv[1] : "ultrafast";
  int deblock = argc > 2 ? atoi(argv[2]) : 0;
  int transform8x8 = argc > 3 ? atoi(argv[3]) : 0;
  int width = 854, height = 480;

  x264_param_t param;
  x264_param_default_preset(&param, preset, "zerolatency");
  param.i_width = width;
  param.i_height = height;
  param.analyse.inter &= ~X264_ANALYSE_PSUB16x16;
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
  param.analyse.b_transform_8x8 = transform8x8;
  param.analyse.i_chroma_qp_offset = 0;
  param.rc.i_rc_method = X264_RC_CQP;
  param.rc.i_qp_constant = param.rc.i_qp_min = param.rc.i_qp_max = 32;
  param.rc.f_ip_factor = 1.0;
  param.b_repeat_headers = 0;
  param.b_aud = 0;
  param.b_drh_mode = 1;
  param.i_threads = 1;
  param.b_sliced_threads = 0;
  param.i_slice_count = 1;
  param.i_log_level = X264_LOG_NONE;
  /* deblocking_filter_control_present in the pad's PPS is 1 */
  param.b_deblocking_filter = deblock ? 1 : 0;

  x264_param_apply_profile(&param, "high");

  x264_t* enc = x264_encoder_open(&param);
  if (!enc) { fprintf(stderr, "x264_encoder_open failed\n"); return 1; }

  x264_nal_t* nals; int nnals;
  if (x264_encoder_headers(enc, &nals, &nnals) < 0) {
    fprintf(stderr, "headers failed\n"); return 1;
  }
  printf("preset=%s deblock=%d transform8x8=%d  sps_id_poc=%d\n",
         preset, deblock, transform8x8, param.i_bframe ? 0 : 2);
  for (int i = 0; i < nnals; i++) {
    int type = nals[i].i_payload > 0 ? (nals[i].p_payload[0] & 0x1F) : -1;
    /* payload includes the start code; strip 00 00 00 01 / 00 00 01 */
    uint8_t* p = nals[i].p_payload; int n = nals[i].i_payload;
    while (n > 0 && p[0] == 0) { p++; n--; }
    if (n > 0 && p[0] == 1) { p++; n--; }
    if (n > 0) type = p[0] & 0x1F;
    const char* nm = type == 7 ? "SPS" : type == 8 ? "PPS" : "other";
    printf("  %s: ", nm);
    for (int j = 0; j < n; j++) printf("%02x", p[j]);
    printf("\n");
  }

  /* also encode a frame so we can inspect a real slice header */
  x264_picture_t pic_in, pic_out;
  x264_picture_alloc(&pic_in, X264_CSP_I420, width, height);
  memset(pic_in.img.plane[0], 0x80, pic_in.img.i_stride[0] * height);
  memset(pic_in.img.plane[1], 0x80, pic_in.img.i_stride[1] * height / 2);
  memset(pic_in.img.plane[2], 0x80, pic_in.img.i_stride[2] * height / 2);
  pic_in.i_type = X264_TYPE_IDR;
  x264_nal_t* out; int nout;
  int size = x264_encoder_encode(enc, &out, &nout, &pic_in, &pic_out);
  printf("  slice batch: %d nals=%d\n", size, nout);
  for (int i = 0; i < nout; i++) {
    uint8_t* p = out[i].p_payload; int n = out[i].i_payload;
    while (n > 0 && p[0] == 0) { p++; n--; }
    if (n > 0 && p[0] == 1) { p++; n--; }
    if (n > 0 && (p[0] & 0x1F) == 5) {
      printf("  first IDR slice header: ");
      for (int j = 0; j < (n < 16 ? n : 16); j++) printf("%02x", p[j]);
      printf("\n");
      break;
    }
  }
  x264_picture_clean(&pic_in);
  x264_encoder_close(enc);
  return 0;
}
