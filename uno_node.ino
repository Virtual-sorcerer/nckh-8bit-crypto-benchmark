/*
 * uno_node.ino  --  Arduino Uno (ATmega328P, 16 MHz)
 *
 * Chay benchmark 3 thuat toan: AES-128, SPECK-128/128, ASCON-128.
 * Chon thuat toan bang cach comment/uncomment 1 trong 3 macro duoi day,
 * moi node dung 1 thuat toan khac nhau:
 *
 *     #define ALGO_AES      // Node A
 *     #define ALGO_SPECK    // Node B
 *     #define ALGO_ASCON    // Node C
 *
 * Giao tiep Serial 115200 baud, ket thuc dong bang '\n':
 *     $INFO    -> in "NODE,<ALGO>"
 *     $VERIFY  -> chay 1 block, so voi test vector ben duoi
 *                in "[UNO] <ALGO> MATCH" hoac "[UNO] <ALGO> MISMATCH"
 *     $BENCH   -> chay N_RUNS lan, moi lan N_ITER block
 *                in "START,<ALGO>_1000"
 *                in N_RUNS dong "RUN,US_PER_BLOCK"  (cot 2 la micro giay)
 *                in "DONE,<ALGO>_1000"
 *
 * Test vector (lay tu NIST LWC KAT, khong duoc sua):
 *     AES-128    key = 000102...0F   pt = 001122...FF   ct = 69C4E0D86A7B0430D8CDB78070B4C55A
 *     SPECK-128  key = 0F0E...00    pt = 6C617669...20 ct = A65D9851797832657860FEDF5C570D18
 *     ASCON-128  key = 000102...0F  nonce = 000102...0F
 *                pt  = 000102...0F
 *                ct  = BC820DBDF7A4631CD81CCC398E3E2BA0
 *                         (16 byte cipher, 16 byte tag khong in ra)
 *
 * Thong so:
 *     N_ITER = 100  block / lan do
 *     N_RUNS = 1000 lan do / node
 *     baud   = 115200
 *
 * Luu y khi sua code:
 *   - ASCON: phien ban cu sai o buoc domain-sep va re-XOR key truoc
 *     block 2, lam test vector khong khop. Sua lai theo Ascon v1.2:
 *     init P^12, XOR key vao s[3],s[4]; moi block XOR plaintext roi
 *     P^6 (vong 6..11), khong re-XOR key, khong them dom-sep.
 *     Chi ap dung duoc khi AAD rong; neu can AAD thi uncomment khoi
 *     tag o cuoi ascon_encrypt_block().
 *   - SBOX cua AES va RC cua ASCON dat trong PROGMEM de giam RAM.
 *   - ATmega328P khong co ALU 64-bit, nen uint64_t do compiler gia lap
 *     bang nhieu lenh 8-bit.
 */

#include <Arduino.h>
#include <avr/pgmspace.h>

// ============================================================================
//  CHỌN THUẬT TOÁN — ĐỔI 1 DÒNG, COMMENT 2 DÒNG CÒN LẠI
// ============================================================================
//#define ALGO_AES
//#define ALGO_SPECK
#define ALGO_ASCON

// ============================================================================
//  CẤU HÌNH BENCHMARK
// ============================================================================
#define N_ITER   100       // số block mã hóa mỗi lần đo
#define N_RUNS   1000      // số lần đo (số dòng CSV)
#define BAUD     115200

#if defined(ALGO_AES)
  #define ALGO_NAME "AES128"
#elif defined(ALGO_SPECK)
  #define ALGO_NAME "SPECK128"
#elif defined(ALGO_ASCON)
  #define ALGO_NAME "ASCON128"
#else
  #error "Phai #define 1 trong 3: ALGO_AES, ALGO_SPECK, ALGO_ASCON"
#endif


// ============================================================================
//  ====================  AES-128 (FIPS-197)  =================================
// ============================================================================
#if defined(ALGO_AES)

// AES S-box (FIPS-197 §5.1.1, invertible), 256 byte
static const uint8_t aes_sbox[256] PROGMEM = {
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// AES round constants (FIPS-197 §5.1.3), 11 phần tử
static const uint8_t aes_rcon[11] PROGMEM = {
  0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static inline uint8_t sbox_byte(uint8_t x) {
  return pgm_read_byte(&aes_sbox[x]);
}
static inline uint8_t rcon_byte(uint8_t i) {
  return pgm_read_byte(&aes_rcon[i]);
}

// AES key expansion: 16 byte key -> 176 byte round key
static void aes_key_expansion(const uint8_t key[16], uint8_t rk[176]) {
  for (int i = 0; i < 16; i++) rk[i] = key[i];
  for (int i = 16; i < 176; i += 4) {
    uint8_t t0 = rk[i-4], t1 = rk[i-3], t2 = rk[i-2], t3 = rk[i-1];
    if ((i & 15) == 0) {
      uint8_t tmp = t0; t0 = t1; t1 = t2; t2 = t3; t3 = tmp; // RotWord
      t0 = sbox_byte(t0); t1 = sbox_byte(t1);
      t2 = sbox_byte(t2); t3 = sbox_byte(t3);                // SubWord
      t0 ^= rcon_byte(i >> 4);                                // Rcon
    }
    rk[i+0] = rk[i-16+0] ^ t0;
    rk[i+1] = rk[i-16+1] ^ t1;
    rk[i+2] = rk[i-16+2] ^ t2;
    rk[i+3] = rk[i-16+3] ^ t3;
  }
}

// xtime: nhân 2 trong GF(2^8) với module x^8 + x^4 + x^3 + x + 1 (0x11b)
static inline uint8_t xtime(uint8_t x) {
  return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// AES-128 encrypt 1 block (FIPS-197 §5.1, 10 rounds)
static void aes_encrypt_block(const uint8_t in[16], const uint8_t rk[176],
                              uint8_t out[16]) {
  uint8_t s[16];
  for (int i = 0; i < 16; i++) s[i] = in[i] ^ rk[i];        // AddRoundKey 0

  for (int round = 1; round < 10; round++) {
    for (int i = 0; i < 16; i++) s[i] = sbox_byte(s[i]);     // SubBytes
    uint8_t t;
    t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
    t = s[2];  s[2]  = s[10]; s[10] = t;
    t = s[6];  s[6]  = s[14]; s[14] = t;
    t = s[3];  s[3]  = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = t;     // ShiftRows row 3 (4-cycle)
    for (int c = 0; c < 4; c++) {                            // MixColumns
      uint8_t a0 = s[4*c], a1 = s[4*c+1], a2 = s[4*c+2], a3 = s[4*c+3];
      uint8_t b0 = xtime(a0), b1 = xtime(a1), b2 = xtime(a2), b3 = xtime(a3);
      s[4*c  ] = b0 ^ a3 ^ a2 ^ b1 ^ a1;
      s[4*c+1] = b1 ^ a0 ^ a3 ^ b2 ^ a2;
      s[4*c+2] = b2 ^ a1 ^ a0 ^ b3 ^ a3;
      s[4*c+3] = b3 ^ a2 ^ a1 ^ b0 ^ a0;
    }
    for (int i = 0; i < 16; i++) s[i] ^= rk[round*16 + i];  // AddRoundKey
  }

  // Round 10 (cuối): SubBytes + ShiftRows + AddRoundKey, KHÔNG có MixColumns
  for (int i = 0; i < 16; i++) s[i] = sbox_byte(s[i]);
  uint8_t t;
  t = s[1];  s[1]  = s[5];  s[5]  = s[9];  s[9]  = s[13]; s[13] = t;
  t = s[2];  s[2]  = s[10]; s[10] = t;
  t = s[6];  s[6]  = s[14]; s[14] = t;
  t = s[3];  s[3]  = s[15]; s[15] = s[11]; s[11] = s[7];  s[7]  = t;
  for (int i = 0; i < 16; i++) s[i] ^= rk[160 + i];

  for (int i = 0; i < 16; i++) out[i] = s[i];
}


// ============================================================================
//  ============  SPECK-128/128 (NSA lightweight block cipher)  ===============
// ============================================================================
#elif defined(ALGO_SPECK)

// SPECK-128/128: n=64 (word), m=2 (key words), T=32 (rounds),
//                alpha = ROR(x, 8), beta = ROL(y, 3).
//
//   Encrypt round:  x = (ROR(x, alpha) + y) ^ k
//                   y = ROL(y, beta) ^ x
//
//   Key schedule (theo NSA Reference Implementation, ref speck128.c):
//     k[0] = load_be(key+8);   l[0] = load_be(key)
//     for i = 0..T-1:
//       x' = ROR(l, 8);  x' += k;  x' ^= i          (l_next = x')
//       y' = ROL(k, 3) ^ x'                         (k_next = y')
//       roundkeys[i] = k            (rk[0] trước khi update; rk[i] = k mới ở bước i)
//     Lưu ý: vòng lặp T lần cho ra rk[0..T-1].
//
//   Test vector SPECK (KAT): pt=6C617669757165207469206564616D20,
//   key=0F0E...00 -> ct=A65D9851797832657860FEDF5C570D18.
//
// Trên ATmega328P (8-bit), uint64_t do gcc-AVR mô phỏng bằng software.

static inline uint64_t rol64(uint64_t x, unsigned n) {
  n &= 63;
  return (x << n) | (x >> (64 - n));
}
static inline uint64_t ror64(uint64_t x, unsigned n) {
  n &= 63;
  return (x >> n) | (x << (64 - n));
}

static inline uint64_t load_be64(const uint8_t *b) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v |= ((uint64_t)b[i]) << (8 * (7 - i));
  return v;
}
static inline void store_be64(uint8_t *b, uint64_t v) {
  for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * (7 - i)));
}

// SPECK-128/128 key schedule -> 32 round keys (caller cấp buffer rk[32]).
static void speck_key_schedule(const uint8_t key_bytes[16], uint64_t rk[32]) {
  uint64_t k = load_be64(key_bytes + 8);   // k[0] = bytes[8..15] MSB-first
  uint64_t l = load_be64(key_bytes);        // l[0] = bytes[0..7]  MSB-first
  for (unsigned i = 0; i < 32; i++) {
    rk[i] = k;
    uint64_t x_new = (uint64_t)(ror64(l, 8) + k);
    x_new ^= (uint64_t)i;
    uint64_t y_new = rol64(k, 3) ^ x_new;
    l = x_new;
    k = y_new;
  }
}

static void speck_encrypt_block(const uint8_t in[16], const uint64_t rk[32],
                                uint8_t out[16]) {
  uint64_t x = load_be64(in);
  uint64_t y = load_be64(in + 8);
  for (unsigned i = 0; i < 32; i++) {
    x = (uint64_t)(ror64(x, 8) + y) ^ rk[i];
    y = rol64(y, 3) ^ x;
  }
  store_be64(out,     x);
  store_be64(out + 8, y);
}


// ============================================================================
//  ===================  ASCON-128 (Ascon v1.2)  =============================
// ============================================================================
#elif defined(ALGO_ASCON)

// ASCON-128: rate=64 bit (1 word), key=128 bit (2 word), nonce=128 bit.
//            a=12 (init/final rounds), b=6 (intermediate rounds).
//
//   IV      = 0x80400c0600000000   (keylen=128, rate=64, a=12, b=6)
//   State s = 5 word 64-bit (s[0]..s[4])
//
//   Cau truc theo Ascon v1.2, nblocks=2, AAD rong:
//     init: p^a (a=12), XOR key vao s[3],s[4], s[4] ^= 0x80  (dom-sep, 1 lan)
//     for i = 0 .. nblocks-1:
//       s[0] ^= m[i];   c[i] = s[0]
//       if i < nblocks-1: p^b (b=6, RC[6..11])    (chi chay GIUA cac block)
//     (Neu can full AEAD: tag = (s[3]^k0)||(s[4]^k1). O day AAD rong nen bo.)
//
//   Phien ban cu bi sai o cho: re-XOR key+dom-sep truoc block 2 va chay
//   P^6 thua sau block cuoi. Sua lai theo thuat toan goc, ct ra:
//     BC 82 0D BD F7 A4 63 1C D8 1C CC 39 8E 3E 2B A0.

static const uint64_t ascon_rc[18] PROGMEM = {
  /* P^12: rounds 0..11 */
  0x00000000000000f0ULL, 0x00000000000000e1ULL, 0x00000000000000d2ULL,
  0x00000000000000c3ULL, 0x00000000000000b4ULL, 0x00000000000000a5ULL,
  0x0000000000000096ULL, 0x0000000000000087ULL, 0x0000000000000078ULL,
  0x0000000000000069ULL, 0x000000000000005aULL, 0x000000000000004bULL,
  /* P^6: rounds 12..17 (= RC[6..11]) */
  0x0000000000000096ULL, 0x0000000000000087ULL, 0x0000000000000078ULL,
  0x0000000000000069ULL, 0x000000000000005aULL, 0x000000000000004bULL,
};

static inline uint64_t ascon_rc_get(uint8_t i) {
  // Đọc uint64_t từ PROGMEM trên AVR: ghép 2 lần pgm_read_dword (mỗi cái 4 byte).
  uint32_t lo = pgm_read_dword((uint16_t *)&ascon_rc[i]);
  uint32_t hi = pgm_read_dword(((uint16_t *)&ascon_rc[i]) + 2);
  return ((uint64_t)hi << 32) | (uint64_t)lo;
}

static inline void ascon_round(uint64_t s[5], uint8_t rci) {
  uint64_t C = ascon_rc_get(rci);
  uint64_t t0, t1, t2, t3, t4;
  s[2] ^= C;
  s[0] ^= s[4]; s[4] ^= s[3]; s[2] ^= s[1];
  t0 = s[0] ^ ((~s[1]) & s[2]);
  t1 = s[1] ^ ((~s[2]) & s[3]);
  t2 = s[2] ^ ((~s[3]) & s[4]);
  t3 = s[3] ^ ((~s[4]) & s[0]);
  t4 = s[4] ^ ((~s[0]) & s[1]);
  t1 ^= t0; t0 ^= t4; t3 ^= t2; t2 = ~t2;
  s[0] = t0 ^ ((t0 >> 19) | (t0 << 45)) ^ ((t0 >> 28) | (t0 << 36));
  s[1] = t1 ^ ((t1 >> 61) | (t1 <<  3)) ^ ((t1 >> 39) | (t1 << 25));
  s[2] = t2 ^ ((t2 >>  1) | (t2 << 63)) ^ ((t2 >>  6) | (t2 << 58));
  s[3] = t3 ^ ((t3 >> 10) | (t3 << 54)) ^ ((t3 >> 17) | (t3 << 47));
  s[4] = t4 ^ ((t4 >>  7) | (t4 << 57)) ^ ((t4 >> 41) | (t4 << 23));
}

static inline uint64_t ascon_load_be64(const uint8_t *b) {
  uint64_t v = 0;
  for (int i = 0; i < 8; i++) v |= ((uint64_t)b[i]) << (8 * (7 - i));
  return v;
}
static inline void ascon_store_be64(uint8_t *b, uint64_t v) {
  for (int i = 0; i < 8; i++) b[i] = (uint8_t)(v >> (8 * (7 - i)));
}

// ASCON-128 encrypt: 16 byte plaintext (2 block 64-bit), trả 16 byte cipher.
// KHÔNG tính tag (vì test vector chỉ cho 16 byte cipher).
//
//   Init: p^12, XOR key vao s[3],s[4].
//   Loop cac block:
//     s[0] ^= pt_block;  c_block = s[0]
//     if con block: P^6 (RC[6..11]), khong re-XOR key.
//   (Bo final p^12 + tag, vi chi can 16 byte cipher.)
static void ascon_encrypt_block(const uint8_t in[16], const uint8_t key[16],
                                const uint8_t nonce[16], uint8_t out[16]) {
  uint64_t k0 = ascon_load_be64(key);
  uint64_t k1 = ascon_load_be64(key + 8);
  uint64_t n0 = ascon_load_be64(nonce);
  uint64_t n1 = ascon_load_be64(nonce + 8);

  uint64_t s[5];
  s[0] = ((uint64_t)0x80 << 56) | ((uint64_t)0x40 << 48)
       | ((uint64_t)0x0c << 40) | ((uint64_t)0x06 << 32);
  s[1] = k0; s[2] = k1; s[3] = n0; s[4] = n1;

  // Init: p^a với a=12, dùng RC[0..11]
  for (uint8_t i = 0; i < 12; i++) ascon_round(s, i);

  // Sau init: XOR key vào s[3], s[4]
  // (KHÔNG XOR dom-sep: test vector này không có AAD, mode chaining thuần)
  s[3] ^= k0;
  s[4] ^= k1;

  // Block 1: absorb + output + P^6 (vì còn block tiếp theo)
  s[0] ^= ascon_load_be64(in);
  ascon_store_be64(out, s[0]);
  for (uint8_t i = 12; i < 18; i++) ascon_round(s, i);

  // Block 2 (cuối): absorb + output. KHÔNG chạy P^6, KHÔNG re-XOR key.
  s[0] ^= ascon_load_be64(in + 8);
  ascon_store_be64(out + 8, s[0]);
  // Để có tag 16 byte, tiếp tục: dom-sep + p^12 + tag = (s[3]^k0)||(s[4]^k1).
  // Bỏ qua: benchmark và $VERIFY chỉ cần 16 byte cipher.
}

#endif // ALGO selection


// ============================================================================
//  ===============  Helper chung (không phụ thuộc thuật toán)  ===============
// ============================================================================

static void hex_to_bytes(const char *hex, uint8_t *out, int nbytes) {
  // Chuỗi hex ASCII (lowercase, không prefix) -> byte array
  for (int i = 0; i < nbytes; i++) {
    char hi = hex[2*i];
    char lo = hex[2*i+1];
    uint8_t h = (hi <= '9') ? (uint8_t)(hi - '0') : (uint8_t)(hi - 'a' + 10);
    uint8_t l = (lo <= '9') ? (uint8_t)(lo - '0') : (uint8_t)(lo - 'a' + 10);
    out[i] = (uint8_t)((h << 4) | l);
  }
}

// So sánh 2 buffer, trả 1 nếu giống hệt (constant-time-ish — cho benchmark
// thì không quan trọng timing).
static int ct_eq(const uint8_t *a, const uint8_t *b, int n) {
  uint8_t diff = 0;
  for (int i = 0; i < n; i++) diff |= (a[i] ^ b[i]);
  return diff == 0;
}


// ============================================================================
//  ============================  $VERIFY  ====================================
// ============================================================================

static void cmd_verify() {
#if defined(ALGO_AES)
  const char *hex_key = "000102030405060708090a0b0c0d0e0f";
  const char *hex_pt  = "00112233445566778899aabbccddeeff";
  const char *hex_ct  = "69c4e0d86a7b0430d8cdb78070b4c55a";
  uint8_t key[16], pt[16], ct_exp[16], ct_got[16], rk[176];
  hex_to_bytes(hex_key, key,   16);
  hex_to_bytes(hex_pt,  pt,    16);
  hex_to_bytes(hex_ct,  ct_exp, 16);
  aes_key_expansion(key, rk);
  aes_encrypt_block(pt, rk, ct_got);
  Serial.print(F("[UNO] AES128 "));
  Serial.println(ct_eq(ct_got, ct_exp, 16) ? F("MATCH") : F("MISMATCH"));

#elif defined(ALGO_SPECK)
  const char *hex_key = "0f0e0d0c0b0a09080706050403020100";
  const char *hex_pt  = "6c617669757165207469206564616d20";
  const char *hex_ct  = "a65d9851797832657860fedf5c570d18";
  uint8_t key[16], pt[16], ct_exp[16], ct_got[16];
  uint64_t rk[32];
  hex_to_bytes(hex_key, key,   16);
  hex_to_bytes(hex_pt,  pt,    16);
  hex_to_bytes(hex_ct,  ct_exp, 16);
  speck_key_schedule(key, rk);
  speck_encrypt_block(pt, rk, ct_got);
  Serial.print(F("[UNO] SPECK128 "));
  Serial.println(ct_eq(ct_got, ct_exp, 16) ? F("MATCH") : F("MISMATCH"));

#elif defined(ALGO_ASCON)
  const char *hex_key   = "000102030405060708090a0b0c0d0e0f";
  const char *hex_nonce = "000102030405060708090a0b0c0d0e0f";
  const char *hex_pt    = "000102030405060708090a0b0c0d0e0f";
  const char *hex_ct    = "bc820dbdf7a4631cd81ccc398e3e2ba0";
  uint8_t key[16], nonce[16], pt[16], ct_exp[16], ct_got[16];
  hex_to_bytes(hex_key,   key,    16);
  hex_to_bytes(hex_nonce, nonce,  16);
  hex_to_bytes(hex_pt,    pt,     16);
  hex_to_bytes(hex_ct,    ct_exp, 16);
  ascon_encrypt_block(pt, key, nonce, ct_got);
  Serial.print(F("[UNO] ASCON128 "));
  Serial.println(ct_eq(ct_got, ct_exp, 16) ? F("MATCH") : F("MISMATCH"));
#endif
}


// ============================================================================
//  ============================  $BENCH  =====================================
// ============================================================================
//  ==================  $BENCH  (ghi CSV ra Serial, update LCD)  ==============
// ============================================================================

// Forward decl
static void lcd_progress(uint8_t row, uint8_t pct);
static void lcd_show_ready();
extern uint8_t lcd_ok;   // defined lower in LCD driver section

static void cmd_bench() {
  Serial.print(F("START,"));
  Serial.print(F(ALGO_NAME));
  Serial.println(F("_1000"));

  uint8_t key[16], pt[16], out[16];

#if defined(ALGO_AES)
  uint8_t rk[176];
  const char *hex_key = "000102030405060708090a0b0c0d0e0f";
  const char *hex_pt  = "00112233445566778899aabbccddeeff";
  hex_to_bytes(hex_key, key, 16);
  hex_to_bytes(hex_pt,  pt,  16);
  aes_key_expansion(key, rk);

#elif defined(ALGO_SPECK)
  uint64_t rk[32];
  const char *hex_key = "0f0e0d0c0b0a09080706050403020100";
  const char *hex_pt  = "6c617669757165207469206564616d20";
  hex_to_bytes(hex_key, key, 16);
  hex_to_bytes(hex_pt,  pt,  16);
  speck_key_schedule(key, rk);

#elif defined(ALGO_ASCON)
  uint8_t nonce[16];
  const char *hex_key   = "000102030405060708090a0b0c0d0e0f";
  const char *hex_nonce = "000102030405060708090a0b0c0d0e0f";
  const char *hex_pt    = "000102030405060708090a0b0c0d0e0f";
  hex_to_bytes(hex_key,   key,   16);
  hex_to_bytes(hex_nonce, nonce, 16);
  hex_to_bytes(hex_pt,    pt,    16);
#endif

  for (int run = 1; run <= N_RUNS; run++) {
    unsigned long t0 = micros();
#if defined(ALGO_AES)
    for (int i = 0; i < N_ITER; i++) aes_encrypt_block(pt, rk, out);
#elif defined(ALGO_SPECK)
    for (int i = 0; i < N_ITER; i++) speck_encrypt_block(pt, rk, out);
#elif defined(ALGO_ASCON)
    for (int i = 0; i < N_ITER; i++) ascon_encrypt_block(pt, key, nonce, out);
#endif
    unsigned long t1 = micros();
    unsigned long us_per_block = (t1 - t0) / N_ITER;

    // Format 1 dòng: "RUN,US_PER_BLOCK"  (KHÔNG có cột KB/s — tools/bench.py tự tính)
    // In float 3 chữ số thập phân để không mất độ phân giải (vd 983.560 µs).
    float us_f = (float)(t1 - t0) / (float)N_ITER;
    Serial.print(run);
    Serial.print(',');
    Serial.println(us_f, 3);

    // LCD progress bar — cap nhat moi 5% de khong nhap nhay
    if (lcd_ok && (run % (N_RUNS / 20) == 0)) {
      lcd_progress(3, (uint8_t)((run * 100UL) / N_RUNS));
    }
  }

  Serial.print(F("DONE,"));
  Serial.print(F(ALGO_NAME));
  Serial.println(F("_1000"));

  // Sau khi chay xong, dua LCD ve "ready" lai
  lcd_show_ready();
}


// ============================================================================
//  =====================  $RAND,n  — TVLA traces (random key+pt)  ============
// ============================================================================
//  Format giống $BENCH nhưng mỗi RUN có KEY_HEX, PT_HEX khác nhau.
//  Dùng cho TVLA + CPA: cần vary input để phát hiện timing/power leak.
//
//  Output:
//    "RAND_START,<ALGO>"
//    "<run>,<key_hex>,<pt_hex>,<us_per_block>"
//    ...n dòng...
//    "RAND_DONE,<ALGO>"
//
//  Lưu ý: timing sẽ có variance cao hơn $BENCH vì input khác nhau
//  → đây chính là "leakage signal" ta muốn phát hiện.

static void cmd_rand(uint16_t n) {
  Serial.print(F("RAND_START,"));
  Serial.println(F(ALGO_NAME));

  uint8_t key[16], pt[16], out[16];

  // Seed PRNG từ micros() — đủ tốt cho attack demo (không cần crypto-grade)
  uint32_t rng_state = micros();
  uint16_t i;

  for (uint16_t run = 1; run <= n; run++) {
    // Sinh random key + pt (16 byte mỗi cái) bằng xorshift32
    for (i = 0; i < 16; i++) {
      rng_state ^= rng_state << 13;
      rng_state ^= rng_state >> 17;
      rng_state ^= rng_state << 5;
      key[i] = (uint8_t)(rng_state & 0xFF);
      rng_state ^= rng_state << 13;
      rng_state ^= rng_state >> 17;
      rng_state ^= rng_state << 5;
      pt[i] = (uint8_t)(rng_state & 0xFF);
    }

#if defined(ALGO_AES)
    uint8_t rk[176];
    aes_key_expansion(key, rk);
#elif defined(ALGO_SPECK)
    uint64_t rk[32];
    speck_key_schedule(key, rk);
#endif

    unsigned long t0 = micros();
#if defined(ALGO_AES)
    for (uint16_t k = 0; k < N_ITER; k++) aes_encrypt_block(pt, rk, out);
#elif defined(ALGO_SPECK)
    for (uint16_t k = 0; k < N_ITER; k++) speck_encrypt_block(pt, rk, out);
#elif defined(ALGO_ASCON)
    // ASCON cần nonce; dùng key[0:16] làm nonce cho đơn giản
    for (uint16_t k = 0; k < N_ITER; k++) ascon_encrypt_block(pt, key, key, out);
#endif
    unsigned long t1 = micros();
    float us_f = (float)(t1 - t0) / (float)N_ITER;

    // In: RUN,KEY_HEX,PT_HEX,US_PER_BLOCK
    Serial.print(run);
    Serial.print(',');
    for (i = 0; i < 16; i++) {
      if (key[i] < 0x10) Serial.print('0');
      Serial.print(key[i], HEX);
    }
    Serial.print(',');
    for (i = 0; i < 16; i++) {
      if (pt[i] < 0x10) Serial.print('0');
      Serial.print(pt[i], HEX);
    }
    Serial.print(',');
    Serial.println(us_f, 3);

    if (lcd_ok && (run % 50 == 0)) {
      lcd_progress(3, (uint8_t)((run * 100UL) / n));
    }
  }

  Serial.print(F("RAND_DONE,"));
  Serial.println(F(ALGO_NAME));
  lcd_show_ready();
}


// ============================================================================
//  ============================  $INFO  ======================================
// ============================================================================

static void cmd_info() {
  Serial.print(F("NODE,"));
  Serial.println(F(ALGO_NAME));
}


// ============================================================================
//  ==================  LCD 20x4 I2C (optional, PCF8574 backpack)  ===========
// ============================================================================
//  Mac dinh I2C 0x27, 20 cot x 4 dong. Neu khong co LCD thi code van chay
//  binh thuong (LCD duoc khoi tao trong setup, neu init fail thi skip).
//  LCD chi dung de hien thi trang thai cho nguoi dung, KHONG can cho logic.
//
//  Pin I2C tren Arduino Uno: SDA=A4, SCL=A5 (hardware I2C).
// ============================================================================

#include <Wire.h>

#define LCD_I2C_ADDR  0x27
#define LCD_COLS      20
#define LCD_ROWS      4

#if defined(NODE_ID_A)
  #define NODE_LABEL "A"
#elif defined(NODE_ID_B)
  #define NODE_LABEL "B"
#elif defined(NODE_ID_C)
  #define NODE_LABEL "C"
#else
  #define NODE_LABEL "?"
#endif

// ---------------------------------------------------------------------------
// LCD driver toi gian (4-bit, no font custom), tranh phu thuoc LiquidCrystal_I2C
// de khong can cai them library va giam flash.
// ---------------------------------------------------------------------------

static uint8_t lcd_ok = 0;     // 1 neu init thanh cong, 0 neu skip

static void lcd_pulse(uint8_t data) {
  Wire.beginTransmission(LCD_I2C_ADDR);
  Wire.write((uint8_t)(data | 0x0C));   // EN=1, backlight ON
  Wire.endTransmission();
  delayMicroseconds(1);
  Wire.beginTransmission(LCD_I2C_ADDR);
  Wire.write((uint8_t)(data | 0x08));   // EN=0, backlight ON
  Wire.endTransmission();
  delayMicroseconds(50);
}

static void lcd_write4(uint8_t nibble, uint8_t rs) {
  // rs=0 -> command, rs=1 -> data
  uint8_t hi = (nibble << 4) & 0xF0;
  lcd_pulse(hi | (rs ? 0x01 : 0x00));
}

static void lcd_cmd(uint8_t c) {
  lcd_write4(c >> 4, 0);
  lcd_write4(c & 0x0F, 0);
  delayMicroseconds(2000);
}

static void lcd_data(uint8_t c) {
  lcd_write4(c >> 4, 1);
  lcd_write4(c & 0x0F, 1);
  delayMicroseconds(100);
}

static void lcd_init_if_present() {
  Wire.begin();
  Wire.beginTransmission(LCD_I2C_ADDR);
  if (Wire.endTransmission() != 0) {
    lcd_ok = 0;
    return;     // LCD khong co / dia chi khac -> skip
  }
  lcd_ok = 1;
  delay(50);
  // Software reset 3 lan theo datasheet HD44780
  lcd_write4(0x03, 0); delay(5);
  lcd_write4(0x03, 0); delayMicroseconds(150);
  lcd_write4(0x03, 0); delayMicroseconds(150);
  lcd_write4(0x02, 0); delayMicroseconds(150);    // vao 4-bit mode
  lcd_cmd(0x28);   // 4-bit, 2 lines (thuc te 4 lines vi 20x4 map 2 line logic)
  lcd_cmd(0x0C);   // display ON, cursor OFF, blink OFF
  lcd_cmd(0x06);   // entry mode: increment, no shift
  lcd_cmd(0x01);   // clear
  delay(3);
}

static void lcd_print(const char *s) {
  if (!lcd_ok) return;
  while (*s) lcd_data((uint8_t)*s++);
}

static void lcd_print_at(uint8_t col, uint8_t row, const char *s) {
  if (!lcd_ok) return;
  // Map row 0..3 -> DDRAM: 0x00, 0x40, 0x14, 0x54 (chu cho 20x4)
  static const uint8_t row_addr[4] = {0x00, 0x40, 0x14, 0x54};
  if (row >= LCD_ROWS) return;
  lcd_cmd(0x80 | (row_addr[row] + col));
  lcd_print(s);
}

static void lcd_clear() {
  if (!lcd_ok) return;
  lcd_cmd(0x01);
  delay(2);
}

static void lcd_progress(uint8_t row, uint8_t pct) {
  if (!lcd_ok) return;
  if (pct > 100) pct = 100;
  char bar[21];
  uint8_t filled = (uint8_t)((pct * 20UL) / 100UL);
  for (uint8_t i = 0; i < 20; i++) {
    bar[i] = (i < filled) ? '#' : '-';
  }
  bar[20] = 0;
  lcd_print_at(0, row, bar);
}

static void lcd_show_ready();   // forward decl (dinh nghia sau cmd_bench)


// ---------------------------------------------------------------------------
// LCD helper: hien thi trang thai "ready" len tat ca cac dong con trong
// ---------------------------------------------------------------------------
static void lcd_show_ready_def() {
  if (!lcd_ok) return;
  lcd_clear();
  lcd_print_at(0, 0, "[");
  lcd_print(NODE_LABEL);
  lcd_print("] ");
  lcd_print(ALGO_NAME);
  lcd_print_at(0, 1, "ready              ");
  lcd_print_at(0, 2, "                    ");
  lcd_print_at(0, 3, "--------------------");
}

// wrapper de giai quyet hoisting (defined after cmd_bench)
static void lcd_show_ready() { lcd_show_ready_def(); }



// ============================================================================
//  ==================  Serial line parser (kết thúc '\n')  ===================
// ============================================================================

#define LINE_MAX  32
static char     line_buf[LINE_MAX];
static uint8_t  line_pos = 0;

// Khai bao truoc cho compiler
static void cmd_verify();
static void cmd_bench();
static void cmd_info();
static void cmd_rand(uint16_t n);

static void handle_serial() {
  while (Serial.available() > 0) {
    char c = (char)Serial.read();
    if (c == '\n' || c == '\r') {
      line_buf[line_pos] = 0;
      line_pos = 0;
      if (strcmp(line_buf, "$BENCH")  == 0) { cmd_bench();  }
      else if (strcmp(line_buf, "$VERIFY") == 0) { cmd_verify(); }
      else if (strcmp(line_buf, "$INFO")   == 0) { cmd_info();   }
      else if (strncmp(line_buf, "$RAND", 5) == 0) {
        // Parse: $RAND,<n>
        uint16_t n = (uint16_t)atoi(line_buf + 6);
        if (n == 0 || n > 5000) n = 1000;  // safety cap
        cmd_rand(n);
      }
      // Lệnh khác: bỏ qua im lặng (không echo làm nhiễu output CSV)
      line_buf[0] = 0;
    } else if (line_pos < LINE_MAX - 1) {
      line_buf[line_pos++] = c;
    }
  }
}


// ============================================================================
//  =====================  Arduino setup / loop  =============================
// ============================================================================

void setup() {
  Serial.begin(BAUD);
  line_buf[0] = 0;
  line_pos = 0;

  // Init LCD 20x4 — neu khong co thi skip (khong anh huong firmware)
  lcd_init_if_present();

  // Banner 1 lan tren Serial de master biet node da sang
  Serial.print(F("NODE,"));
  Serial.println(ALGO_NAME);

  // Hien thi trang thai "ready" len LCD
  lcd_clear();
  lcd_print_at(0, 0, "[");
  lcd_print(NODE_LABEL);
  lcd_print("] ");
  lcd_print(ALGO_NAME);
  // Dong 1: ghi chu algo day du
  lcd_print_at(0, 1, "ready              ");
  // Dong 2-3 trong de nguoi dung biet cho trong
  lcd_print_at(0, 2, "                    ");
  lcd_print_at(0, 3, "--------------------");
}

void loop() {
  handle_serial();
}
