/* Test fixture: a derived/transformed credential -- same shape as the real keykeeper binary this project
   analysed (per-byte XOR against a repeating key phrase plus an incrementing byte accumulator), but with a
   DIFFERENT expected value and different constants, compiled for
   tests/test_credential_recovery.py -- "transformed/derived credential" scenario. Nothing in the detector
   under test may hardcode this fixture's own expected value or constants. */
#include <stdio.h>
#include <string.h>

static unsigned char cipher[16] = {
    0x33, 0x08, 0x0c, 0x0f, 0x0a, 0x1c, 0x3c, 0x32, 0x14, 0x30, 0x3f, 0x63, 0x64, 0x11, 0x04, 0x45
};
/* (the plaintext this decodes to is a test fixture; it is never written down here as a literal string,
   consistent with the behaviour this fixture tests -- a detector must derive it from the code+data, not
   read it off a comment) */

int main(int argc, char **argv) {
    const char *key = "testkey9";
    puts("== XorCheck v1.0 ==");
    if (argc < 2) {
        puts("usage: xor_check <value>");
        return 1;
    }
    const char *in = argv[1];
    if (strlen(in) != 16) {
        puts("[-] denied.");
        return 1;
    }
    unsigned char acc = 3;
    for (int i = 0; i < 16; i++) {
        if ((unsigned char)(cipher[i] ^ acc ^ key[i % 8]) != (unsigned char)in[i]) {
            puts("[-] denied.");
            return 1;
        }
        acc = (unsigned char)(acc + 5);
    }
    puts("[+] accepted.");
    return 0;
}
