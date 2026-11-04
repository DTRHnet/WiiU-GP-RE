#!/usr/bin/env python3
"""Patch cfg80211 to accept Nintendo's obfuscated CCMP cipher selector.

The Wii U GamePad/console use a4:c0:e1 in place of the standard RSN OUI 00:0f:ac.
Hostapd (built with CONFIG_TENDONIN) advertises that selector in the RSN IE and applies
the 3-byte PTK rotation in userspace. The problem is downstream: cfg80211 validates the
key cipher against the driver's advertised cipher_suites, and iwlwifi only lists the
standard ones, so key installation fails with -EINVAL.

Rewriting the cipher to standard CCMP here means:
  * iwlwifi/mac80211 install a normal CCMP key (they accept it),
  * the beacon still carries a4:c0:e1 because that IE is built by hostapd, and
  * the PTK still matches the GamePad, because hostapd already rotated it before
    handing it to the kernel.

Run with sudo.  Idempotent.
"""
import sys

SRC = "/home/kali/Wiiu/kernel/linux-source-7.1/net/wireless/util.c"

OLD = """int cfg80211_validate_key_settings(struct cfg80211_registered_device *rdev,
				   struct key_params *params, int key_idx,
				   bool pairwise, const u8 *mac_addr)
{
	if (!cfg80211_valid_key_idx(rdev, key_idx, pairwise))
		return -EINVAL;"""

NEW = """int cfg80211_validate_key_settings(struct cfg80211_registered_device *rdev,
				   struct key_params *params, int key_idx,
				   bool pairwise, const u8 *mac_addr)
{
	/* DRC patch: the Wii U GamePad/console replace the standard RSN OUI
	 * 00:0f:ac with Nintendo's a4:c0:e1. hostapd (CONFIG_TENDONIN) advertises
	 * that selector on air and performs the 3-byte PTK rotation itself, but
	 * cfg80211 validates key ciphers against the driver's cipher_suites, and
	 * the driver only knows the standard ones - so key installation fails
	 * with -EINVAL. Rewrite the Nintendo CCMP selector (a4:c0:e1:4) to the
	 * standard CCMP suite: the driver installs a normal CCMP key, the beacon
	 * is unaffected (hostapd builds that IE), and the rotated PTK still
	 * matches the GamePad.
	 */
	if (params->cipher == 0xa4c0e104)	/* a4:c0:e1:4 Nintendo CCMP */
		params->cipher = WLAN_CIPHER_SUITE_CCMP;

	if (!cfg80211_valid_key_idx(rdev, key_idx, pairwise))
		return -EINVAL;"""


def main():
    s = open(SRC).read()
    if "DRC patch: the Wii U GamePad/console replace" in s:
        print("already patched")
        return 0
    if OLD not in s:
        print("ANCHOR NOT FOUND - kernel source differs; inspect util.c manually")
        return 1
    open(SRC, "w").write(s.replace(OLD, NEW, 1))
    print("PATCHED cfg80211_validate_key_settings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
