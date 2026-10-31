/* Test fixture: no credential at all, but several strings shaped like one (a build hash, a UUID-like
   constant, a version tag) that a naive heuristic could mistake for a secret. For
   tests/test_credential_recovery.py -- "incorrect candidate / false positive" scenario. */
#include <stdio.h>

int main(void) {
    const char *build_hash = "f4a9c21e7b8d1206";          /* 16 hex chars: matches the hex-secret shape */
    const char *session_tag = "Build-v2.4.1-rc3";          /* mixed letters/digits/punct: matches the generic shape */
    printf("build %s session %s\n", build_hash, session_tag);
    return 0;
}
