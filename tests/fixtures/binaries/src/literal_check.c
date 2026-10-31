/* Test fixture: a literal, statically-embedded credential checked with strcmp. Compiled for
   tests/test_credential_recovery.py -- "recoverable embedded credential" scenario. */
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    const char *expected = "SuperSecret123!";
    if (argc < 2) {
        puts("usage: literal_check <value>");
        return 1;
    }
    if (strcmp(argv[1], expected) == 0) {
        puts("[+] accepted.");
        return 0;
    }
    puts("[-] denied.");
    return 1;
}
