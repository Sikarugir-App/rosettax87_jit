#include <cstdarg>

extern "C"
    __attribute__((used, visibility("default"), section("__TEXT,__text"), noinline, retain)) void
    start() {
}

namespace std {
inline namespace __1 {
// Freestanding trap for the no-exceptions throw-helpers pulled in by
// std::optional / std::function from rosetta_core_runtime. Newer libc++
// (macos-26 CI) routes these through __libcpp_verbose_abort; -nostdlib does
// not provide it. Match its signature and mangling exactly.
[[noreturn]] __attribute__((used, visibility("default")))
void __libcpp_verbose_abort(const char* /*fmt*/, ...) {
    __builtin_trap();
}
} // namespace __1
} // namespace std
