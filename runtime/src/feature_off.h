// LEONIDA_OFF="name[,name...]": turns off individual compatibility behaviours, for bisecting a regression during the
// retail boot work. Unknown names are ignored. Read once per process.
#pragma once

#include <windows.h>

#include <cstdlib>
#include <cstring>

namespace leonida {

inline bool feature_off(const char* name) {
    char spec[512];
    size_t length = 0;
    if (getenv_s(&length, spec, sizeof spec, "LEONIDA_OFF") != 0 || length <= 1) return false;
    const size_t n = std::strlen(name);
    for (const char* p = spec; (p = std::strstr(p, name)) != nullptr; p += n) {
        const bool start = p == spec || p[-1] == ',' || p[-1] == ' ';
        const bool end = p[n] == '\0' || p[n] == ',' || p[n] == ' ';
        if (start && end) return true;
    }
    return false;
}

}  // namespace leonida
