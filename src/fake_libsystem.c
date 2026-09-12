__attribute__((visibility("default")))
void
libSystem_initializer(int argc, const char *argv[], const char *envp[], const char *apple[],
    const void *vars)
{
	(void)argc;
	(void)argv;
	(void)envp;
	(void)apple;
	(void)vars;
}

__attribute__((visibility("default")))
void
_libSystem_initializer(int argc, const char *argv[], const char *envp[], const char *apple[],
    const void *vars)
{
	libSystem_initializer(argc, argv, envp, apple, vars);
}

char* getenv(const char *key) {
    return 0;
}

#include <stdarg.h>

/* Darwin/arm64 syscall helper: traps via svc #0x80 (NOT svc #0). */
static long
sc6(long n, long a, long b, long c, long d, long e, long f)
{
	register long x16 asm("x16") = n;
	register long x0 asm("x0") = a;
	register long x1 asm("x1") = b;
	register long x2 asm("x2") = c;
	register long x3 asm("x3") = d;
	register long x4 asm("x4") = e;
	register long x5 asm("x5") = f;
	asm volatile("svc #0x80" : "+r"(x0) : "r"(x16), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "cc", "memory");
	return x0;
}

/* Real open(2) via the correct Darwin arm64 syscall trap (svc #0x80), with
 * the variadic mode argument forwarded when O_CREAT is set. The previous
 * naked version used svc #0 (wrong trap on Darwin/arm64) and dropped mode. */
int open(const char *path, int flags, ...) {
    va_list ap;
    int mode = 0;
    if (flags & 0x0200 /* O_CREAT */) {
        va_start(ap, flags);
        mode = va_arg(ap, int);
        va_end(ap);
    }
    return (int)sc6(5, (long)path, (long)flags, (long)mode, 0, 0, 0);
}

int strcmp(const char* s1, const char* s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++; s2++;
    }
    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}
