#include <stdint.h>
#include <stdio.h>

#define ITERS 2000000000UL

int main() {
  uint64_t a = 1, b = 2, c = 3, d = 4, e = 5, f = 6, g = 7, h = 8;

  for (uint64_t i = 0; i < ITERS; i++) {
    a += a;
    b += b;
    c += c;
    d += d;
    e += e;
    f += f;
    g += g;
    h += h;
  }

  printf("%lu\n", a + b + c + d + e + f + g + h);
  return 0;
}
