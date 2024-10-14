/* source for TSC measurement code:
 * https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/ia-32-ia-64-benchmark-code-execution-paper.pdf
 */

#define MEASURE_BEFORE(cycles_high, cycles_low) \
  asm volatile( \
    "CPUID\n\t" \
    "RDTSC\n\t" \
    "mov %%edx, %0\n\t" \
    "mov %%eax, %1\n\t" \
    : "=r" (cycles_high), "=r" (cycles_low) \
    :: "%rax", "%rbx", "%rcx", "%rdx");

#define MEASURE_AFTER(cycles_high, cycles_low) \
  asm volatile( \
    "RDTSCP\n\t" \
    "mov %%edx, %0\n\t" \
    "mov %%eax, %1\n\t" \
    "CPUID\n\t" \
    : "=r" (cycles_high), "=r" (cycles_low) \
    :: "%rax", "%rbx", "%rcx", "%rdx");

#define MAKESTRING2(x) #x
#define MAKESTRING(x) MAKESTRING2(x)

static int64_t make_int64(uint32_t high, uint32_t low) {
  return (((int64_t) high) << 32) | (int64_t) low;
}



#define MEASURE_FUNC_AND_COUNT(code_to_measure, out_buffer, index) {                             \
    uint32_t cycles_low_before, cycles_high_before;                                              \
    uint32_t cycles_low_after, cycles_high_after;                                                \
    if (out_buffer)            {                                                                 \
       MEASURE_BEFORE(cycles_high_before, cycles_low_before);                                    \
       do {                                                                                      \
          code_to_measure                                                                        \
       } while (0);                                                                              \
       MEASURE_AFTER(cycles_high_after, cycles_low_after);                                       \
                                                                                                 \
       if (index < SAFEFETCH_MEASURE_MAX) {                                                      \
          out_buffer[index++] = make_int64(cycles_high_after, cycles_low_after)                  \
                 - make_int64(cycles_high_before, cycles_low_before) - rdmsr_ovr;                \
       }                                                                                         \
     }                                                                                           \
     else {                                                                                      \
          code_to_measure                                                                        \
     }                                                                                           \
  }



#define MEASURE_FUNC(code_to_measure, out_buffer, index) {                                       \
    uint32_t cycles_low_before, cycles_high_before;                                              \
    uint32_t cycles_low_after, cycles_high_after;                                                \
    if (out_buffer)            {                                                                 \
       MEASURE_BEFORE(cycles_high_before, cycles_low_before);                                    \
       do {                                                                                      \
          code_to_measure                                                                        \
       } while (0);                                                                              \
       MEASURE_AFTER(cycles_high_after, cycles_low_after);                                       \
                                                                                                 \
       if (index < SAFEFETCH_MEASURE_MAX) {                                                      \
          out_buffer[index] = make_int64(cycles_high_after, cycles_low_after)                    \
                 - make_int64(cycles_high_before, cycles_low_before) - rdmsr_ovr;                \
       }                                                                                         \
     }                                                                                           \
     else {                                                                                      \
          code_to_measure                                                                        \
     }                                                                                           \
  }
