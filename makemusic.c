#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define FIFO_SIZE (2048 * 8)
#define DUR_4 0
#define DUR_8_8 1
#define DUR_3_3_3 2
#define DUR_16_16_16_16 3
#define DUR_8DOT_16 4
#define DUR_8_16_16 5
#define DUR_16_16_8 6

static uint8_t bit_fifo[FIFO_SIZE];
static int fifo_head = 0, fifo_tail = 0, fifo_count = 0;

static const uint8_t rhythms[9] = {
    DUR_4, DUR_4, DUR_8_8, DUR_8_8, DUR_8DOT_16,
    DUR_3_3_3, DUR_8_16_16, DUR_16_16_8, DUR_16_16_16_16
};

static uint32_t sha_state[8];
static uint64_t sha_counter = 0;

static uint32_t random_bits(int num_bits);

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];

    for (int i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (int i = 16; i < 64; i++)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

static void prng_init(const char *seed) {
    sha_state[0] = 0x6a09e667; sha_state[1] = 0xbb67ae85;
    sha_state[2] = 0x3c6ef372; sha_state[3] = 0xa54ff53a;
    sha_state[4] = 0x510e527f; sha_state[5] = 0x9b05688c;
    sha_state[6] = 0x1f83d9ab; sha_state[7] = 0x5be0cd19;

    uint8_t block[64] = {0};
    size_t len = strlen(seed);
    size_t i;

    for (i = 0; i < len && i < 55; i++)
        block[i] = seed[i];
    block[i] = 0x80;
    uint64_t bit_len = len * 8;
    for (int j = 0; j < 8; j++)
        block[63 - j] = (bit_len >> (j * 8)) & 0xff;

    sha256_transform(sha_state, block);
    sha_counter = 0;
}

static uint32_t prng_next(void) {
    uint8_t block[64] = {0};
    for (int i = 0; i < 8; i++)
        block[i] = (sha_counter >> (56 - i * 8)) & 0xff;
    block[8] = 0x80;
    block[62] = 0x02;
    block[63] = 0x00;

    uint32_t temp_state[8];
    memcpy(temp_state, sha_state, sizeof(temp_state));
    sha256_transform(temp_state, block);

    sha_counter++;
    return temp_state[0];
}

static void bits_ins(int num_bits, uint32_t n) {
    for (int i = 0; i < num_bits; i++) {
        if (fifo_count < FIFO_SIZE) {
            bit_fifo[fifo_head] = n & 1;
            fifo_head = (fifo_head + 1) % FIFO_SIZE;
            fifo_count++;
        }
        n >>= 1;
    }
}

static bool fifo_remove_bit(uint8_t *bit) {
    if (fifo_count > 0) {
        *bit = bit_fifo[fifo_tail];
        fifo_tail = (fifo_tail + 1) % FIFO_SIZE;
        fifo_count--;
        return true;
    }
    return false;
}

static uint32_t random_bits(int num_bits) {
    uint8_t b;
    uint32_t res = 0;
    while (num_bits > 0) {
        if (fifo_remove_bit(&b)) {
            res = (res << 1) | b;
            num_bits--;
        } else {
            bits_ins(32, prng_next());
        }
    }
    return res;
}

static void insert_note(char *buf, int k, int *j, int *octave_state) {
    k /= 2;
    if (k < 3) {
        if (*octave_state != 4) {
            *octave_state = 4;
            buf[(*j)++] = '4';
        }
        if (!k)
            buf[(*j)++] = 'G';
        else
            buf[(*j)++] = 'A' + (k - 1);
    } else {
        if (*octave_state != 5) {
            *octave_state = 5;
            buf[(*j)++] = '5';
        }
        buf[(*j)++] = 'A' + (k - 1);
    }
}

static char* generate_music_notation(void) {
    char *buf = calloc(256, 1);
    int j = 0, octave_state = 5;

    fifo_head = fifo_tail = fifo_count = 0;

    buf[j++] = '5';

    int last_duration = -1;

    for (int i = 0; i < 8; i++) {
        int n = random_bits(8);
        int duration = rhythms[n % 9];

        int k, k2;

        switch (duration) {
            case DUR_8_8:
                if (last_duration != DUR_8_8)
                    buf[j++] = 'e';
                insert_note(buf, random_bits(4), &j, &octave_state);
                insert_note(buf, random_bits(4), &j, &octave_state);
                break;
            case DUR_8DOT_16:
                buf[j++] = 'e';
                buf[j++] = '.';
                insert_note(buf, random_bits(4), &j, &octave_state);
                buf[j++] = 's';
                insert_note(buf, random_bits(4), &j, &octave_state);
                duration = DUR_16_16_16_16;
                break;
            case DUR_3_3_3:
                if (last_duration != DUR_3_3_3) {
                    buf[j++] = 'e';
                    buf[j++] = 't';
                }
                insert_note(buf, random_bits(4), &j, &octave_state);
                insert_note(buf, random_bits(4), &j, &octave_state);
                insert_note(buf, random_bits(4), &j, &octave_state);
                break;
            case DUR_8_16_16:
                if (last_duration != DUR_8_8)
                    buf[j++] = 'e';
                insert_note(buf, random_bits(4), &j, &octave_state);
                buf[j++] = 's';
                insert_note(buf, random_bits(4), &j, &octave_state);
                insert_note(buf, random_bits(4), &j, &octave_state);
                duration = DUR_16_16_16_16;
                break;
            case DUR_16_16_8:
                if (last_duration != DUR_16_16_16_16)
                    buf[j++] = 's';
                insert_note(buf, random_bits(4), &j, &octave_state);
                insert_note(buf, random_bits(4), &j, &octave_state);
                buf[j++] = 'e';
                insert_note(buf, random_bits(4), &j, &octave_state);
                duration = DUR_8_8;
                break;
            case DUR_16_16_16_16:
                if (last_duration != DUR_16_16_16_16)
                    buf[j++] = 's';
                k = random_bits(4);
                k2 = random_bits(4);
                insert_note(buf, k, &j, &octave_state);
                insert_note(buf, k2, &j, &octave_state);
                insert_note(buf, k, &j, &octave_state);
                insert_note(buf, k2, &j, &octave_state);
                break;
            default:
                if (last_duration != DUR_4)
                    buf[j++] = 'q';
                insert_note(buf, random_bits(4), &j, &octave_state);
        }
        last_duration = duration;
    }
    buf[j] = '\0';
    return buf;
}

static void convert_to_abc(const char *notation, const char *title) {
    int current_octave = 4;
    double current_duration = 1.0;

    printf("X:1\nT:%s\nM:4/4\nL:1/4\nQ:1/4=120\nK:C\n", title);

    for (const char *p = notation; *p; p++) {
        switch (*p) {
            case '0': case '1': case '2': case '3': case '4':
            case '5': case '6': case '7': case '8': case '9':
                current_octave = *p - '0';
                break;
            case 'w': current_duration = 4.0; break;
            case 'h': current_duration = 2.0; break;
            case 'q': current_duration = 1.0; break;
            case 'e': current_duration = 0.5; break;
            case 's': current_duration = 0.25; break;
            case 't': current_duration = current_duration * 2.0 / 3.0; break;
            case '.': current_duration = current_duration * 1.5; break;
            case 'R': {
                putchar('z');
                if (current_duration >= 4.0) putchar('4');
                else if (current_duration >= 2.0) putchar('2');
                else if (current_duration >= 0.5 && current_duration < 1.0) putchar('/');
                else if (current_duration >= 0.25 && current_duration < 0.5) {
                    putchar('/'); putchar('/');
                } else if (current_duration < 0.25) {
                    putchar('/'); putchar('/'); putchar('/');
                }
                putchar(' ');
                break;
            }
            case 'A': case 'B': case 'C': case 'D':
            case 'E': case 'F': case 'G': {
                if (current_octave >= 5) {
                    putchar(*p + ('a' - 'A'));
                    for (int i = 0; i < current_octave - 5; i++) putchar('\'');
                } else if (current_octave == 4) {
                    putchar(*p);
                } else {
                    putchar(*p);
                    for (int i = 0; i < 4 - current_octave; i++) putchar(',');
                }
                if (current_duration >= 4.0) putchar('4');
                else if (current_duration >= 2.0) putchar('2');
                else if (current_duration >= 0.5 && current_duration < 1.0) putchar('/');
                else if (current_duration >= 0.25 && current_duration < 0.5) {
                    putchar('/'); putchar('/');
                } else if (current_duration < 0.25) {
                    putchar('/'); putchar('/'); putchar('/');
                }
                putchar(' ');
                break;
            }
        }
    }
    putchar('\n');
}

int main(int argc, char *argv[]) {
    const char *seed = (argc > 1) ? argv[1] : "default";

    prng_init(seed);

    size_t capacity = 2048;
    char *full = malloc(capacity);
    full[0] = '\0';

    char *part1 = generate_music_notation();
    char *part2 = generate_music_notation();

    size_t part1_len = strlen(part1);
    size_t part2_len = strlen(part2);
    size_t needed = (part1_len * 2) + (part2_len * 2) + 1;

    if (needed > capacity) {
        while (capacity < needed) {
            capacity *= 2;
        }
        full = realloc(full, capacity);
    }

    strcat(full, part1);
    strcat(full, part1);
    strcat(full, part2);
    strcat(full, part2);

    free(part1);
    free(part2);

    convert_to_abc(full, seed);

    free(full);
    return 0;
}
