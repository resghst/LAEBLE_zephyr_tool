#include "ecc.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define NUM_ECC_DIGITS (ECC_BYTES/8)
#define MAX_TRIES 16

typedef unsigned int uint;

#if defined(__SIZEOF_INT128__) || ((__clang_major__ * 100 + __clang_minor__) >= 302)
    #define SUPPORTS_INT128 1
#else
    #define SUPPORTS_INT128 0
#endif

#if SUPPORTS_INT128
typedef unsigned __int128 uint128_t;
#else
typedef struct
{
    uint64_t m_low;
    uint64_t m_high;
} uint128_t;
#endif

// typedef struct EccPoint
// {
//     uint64_t x[NUM_ECC_DIGITS];
//     uint64_t y[NUM_ECC_DIGITS];
// } EccPoint;

#define CONCAT1(a, b) a##b
#define CONCAT(a, b) CONCAT1(a, b)

#define Curve_P_16 {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFDFFFFFFFF}
#define Curve_P_24 {0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFFFFFFFFFEull, 0xFFFFFFFFFFFFFFFFull}
#define Curve_P_32 {0xFFFFFFFFFFFFFFFFull, 0x00000000FFFFFFFFull, 0x0000000000000000ull, 0xFFFFFFFF00000001ull}
#define Curve_P_48 {0x00000000FFFFFFFF, 0xFFFFFFFF00000000, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

#define Curve_B_16 {0xD824993C2CEE5ED3, 0xE87579C11079F43D}
#define Curve_B_24 {0xFEB8DEECC146B9B1ull, 0x0FA7E9AB72243049ull, 0x64210519E59C80E7ull}
#define Curve_B_32 {0x3BCE3C3E27D2604Bull, 0x651D06B0CC53B0F6ull, 0xB3EBBD55769886BCull, 0x5AC635D8AA3A93E7ull}
#define Curve_B_48 {0x2A85C8EDD3EC2AEF, 0xC656398D8A2ED19D, 0x0314088F5013875A, 0x181D9C6EFE814112, 0x988E056BE3F82D19, 0xB3312FA7E23EE7E4}

#define Curve_G_16 { \
    {0x0C28607CA52C5B86, 0x161FF7528B899B2D}, \
    {0xC02DA292DDED7A83, 0xCF5AC8395BAFEB13}}

#define Curve_G_24 { \
    {0xF4FF0AFD82FF1012ull, 0x7CBF20EB43A18800ull, 0x188DA80EB03090F6ull}, \
    {0x73F977A11E794811ull, 0x631011ED6B24CDD5ull, 0x07192B95FFC8DA78ull}}
    
#define Curve_G_32 { \
    {0xF4A13945D898C296ull, 0x77037D812DEB33A0ull, 0xF8BCE6E563A440F2ull, 0x6B17D1F2E12C4247ull}, \
    {0xCBB6406837BF51F5ull, 0x2BCE33576B315ECEull, 0x8EE7EB4A7C0F9E16ull, 0x4FE342E2FE1A7F9Bull}}

#define Curve_G_48 { \
    {0x3A545E3872760AB7, 0x5502F25DBF55296C, 0x59F741E082542A38, 0x6E1D3B628BA79B98, 0x8EB1C71EF320AD74, 0xAA87CA22BE8B0537}, \
    {0x7A431D7C90EA0E5F, 0x0A60B1CE1D7E819D, 0xE9DA3113B5F0B8C0, 0xF8F41DBD289A147C, 0x5D9E98BF9292DC29, 0x3617DE4A96262C6F}}

#define Curve_N_16 {0x75A30D1B9038A115, 0xFFFFFFFE00000000}
#define Curve_N_24 {0x146BC9B1B4D22831ull, 0xFFFFFFFF99DEF836ull, 0xFFFFFFFFFFFFFFFFull}
#define Curve_N_32 {0xF3B9CAC2FC632551ull, 0xBCE6FAADA7179E84ull, 0xFFFFFFFFFFFFFFFFull, 0xFFFFFFFF00000000ull}
#define Curve_N_48 {0xECEC196ACCC52973, 0x581A0DB248B0A77A, 0xC7634D81F4372DDF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF}

// static uint64_t curve_p[NUM_ECC_DIGITS] = CONCAT(Curve_P_, ECC_CURVE);
// static uint64_t curve_b[NUM_ECC_DIGITS] = CONCAT(Curve_B_, ECC_CURVE);
// static EccPoint curve_G = CONCAT(Curve_G_, ECC_CURVE);
// static uint64_t curve_n[NUM_ECC_DIGITS] = CONCAT(Curve_N_, ECC_CURVE);

struct uECC_Curve_t p192r1 = {
    .num_words = 24,
    .num_digits = 3,
    .p = Curve_P_24,
    .n = Curve_N_24,
    .G = Curve_G_24,
    .b = Curve_B_24
};
static uECC_Curve p192 = &p192r1;

struct uECC_Curve_t p256r1 = {
    .num_words = 32,
    .num_digits = 4,
    .p = Curve_P_32,
    .n = Curve_N_32,
    .G = Curve_G_32,
    .b = Curve_B_32
};
static uECC_Curve p256 = &p256r1;

#if (defined(_WIN32) || defined(_WIN64))
/* Windows */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>

static int getRandomNumber(uint64_t *p_vli)
{
    HCRYPTPROV l_prov;
    if(!CryptAcquireContext(&l_prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        return 0;
    }

    CryptGenRandom(l_prov, ECC_BYTES, (BYTE *)p_vli);
    CryptReleaseContext(l_prov, 0);
    
    return 1;
}

#else /* _WIN32 */

/* Assume that we are using a POSIX-like system with /dev/urandom or /dev/random. */
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#ifndef O_CLOEXEC
    #define O_CLOEXEC 0
#endif

static int getRandomNumber(uint64_t *p_vli, uECC_Curve curve)
{
    int l_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if(l_fd == -1)
    {
        l_fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
        if(l_fd == -1)
        {
            return 0;
        }
    }
    
    char *l_ptr = (char *)p_vli;
    size_t l_left = curve->num_words;
    while(l_left > 0)
    {
        int l_read = read(l_fd, l_ptr, l_left);
        if(l_read <= 0)
        { // read failed
            close(l_fd);
            return 0;
        }
        l_left -= l_read;
        l_ptr += l_read;
    }
    
    close(l_fd);
    return 1;
}

#endif /* _WIN32 */

static void vli_clear(uint64_t *p_vli, uECC_Curve curve)
{
    uint i;
    for(i=0; i< curve->num_digits; ++i)
    {
        p_vli[i] = 0;
    }
}

/* Returns 1 if p_vli == 0, 0 otherwise. */
static int vli_isZero(uint64_t *p_vli, uECC_Curve curve)
{
    uint i;
    for(i = 0; i < curve->num_digits; ++i)
    {
        if(p_vli[i])
        {
            return 0;
        }
    }
    return 1;
}

/* Returns nonzero if bit p_bit of p_vli is set. */
static uint64_t vli_testBit(uint64_t *p_vli, uint p_bit)
{
    return (p_vli[p_bit/64] & ((uint64_t)1 << (p_bit % 64)));
}

/* Counts the number of 64-bit "digits" in p_vli. */
static uint vli_numDigits(uint64_t *p_vli, uECC_Curve curve)
{
    int i;
    /* Search from the end until we find a non-zero digit.
       We do it in reverse because we expect that most digits will be nonzero. */
    for(i = curve->num_digits - 1; i >= 0 && p_vli[i] == 0; --i)
    {
    }

    return (i + 1);
}

/* Counts the number of bits required for p_vli. */
static uint vli_numBits(uint64_t *p_vli, uECC_Curve curve)
{
    uint i;
    uint64_t l_digit;
    
    uint l_numDigits = vli_numDigits(p_vli, curve);
    if(l_numDigits == 0)
    {
        return 0;
    }

    l_digit = p_vli[l_numDigits - 1];
    for(i=0; l_digit; ++i)
    {
        l_digit >>= 1;
    }
    
    return ((l_numDigits - 1) * 64 + i);
}

/* Sets p_dest = p_src. */
static void vli_set(uint64_t *p_dest, uint64_t *p_src, uECC_Curve curve)
{
    uint i;
    for(i=0; i< curve->num_digits; ++i)
    {
        p_dest[i] = p_src[i];
    }
}

/* Returns sign of p_left - p_right. */
static int vli_cmp(uint64_t *p_left, uint64_t *p_right, uECC_Curve curve)
{
    int i;
    for(i = curve->num_digits-1; i >= 0; --i)
    {
        if(p_left[i] > p_right[i])
        {
            return 1;
        }
        else if(p_left[i] < p_right[i])
        {
            return -1;
        }
    }
    return 0;
}

/* Computes p_result = p_in << c, returning carry. Can modify in place (if p_result == p_in). 0 < p_shift < 64. */
static uint64_t vli_lshift(uint64_t *p_result, uint64_t *p_in, uint p_shift, uECC_Curve curve)
{
    uint64_t l_carry = 0;
    uint i;
    for(i = 0; i < curve->num_digits; ++i)
    {
        uint64_t l_temp = p_in[i];
        p_result[i] = (l_temp << p_shift) | l_carry;
        l_carry = l_temp >> (64 - p_shift);
    }
    
    return l_carry;
}

/* Computes p_vli = p_vli >> 1. */
static void vli_rshift1(uint64_t *p_vli, uECC_Curve curve)
{
    uint64_t *l_end = p_vli;
    uint64_t l_carry = 0;
    
    p_vli += curve->num_digits;
    while(p_vli-- > l_end)
    {
        uint64_t l_temp = *p_vli;
        *p_vli = (l_temp >> 1) | l_carry;
        l_carry = l_temp << 63;
    }
}

/* Computes p_result = p_left + p_right, returning carry. Can modify in place. */
static uint64_t vli_add(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uECC_Curve curve)
{
    uint64_t l_carry = 0;
    uint i;
    for(i=0; i< curve->num_digits; ++i)
    {
        uint64_t l_sum = p_left[i] + p_right[i] + l_carry;
        if(l_sum != p_left[i])
        {
            l_carry = (l_sum < p_left[i]);
        }
        p_result[i] = l_sum;
    }
    return l_carry;
}

/* Computes p_result = p_left - p_right, returning borrow. Can modify in place. */
static uint64_t vli_sub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uECC_Curve curve)
{
    uint64_t l_borrow = 0;
    uint i;
    for(i=0; i< curve->num_digits; ++i)
    {
        uint64_t l_diff = p_left[i] - p_right[i] - l_borrow;
        if(l_diff != p_left[i])
        {
            l_borrow = (l_diff > p_left[i]);
        }
        p_result[i] = l_diff;
    }
    return l_borrow;
}


/* Computes p_result = p_left * p_right. */
static void vli_mult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uECC_Curve curve)
{
    uint128_t r01 = 0;
    uint64_t r2 = 0;
    
    uint i, k;
    
    /* Compute each digit of p_result in sequence, maintaining the carries. */
    for(k=0; k < curve->num_digits *2 - 1; ++k)
    {
        uint l_min = (k < curve->num_digits ? 0 : (k + 1) - curve->num_digits);
        for(i=l_min; i<=k && i<curve->num_digits; ++i)
        {
            uint128_t l_product = (uint128_t)p_left[i] * p_right[k-i];
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint64_t)r01;
        r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
        r2 = 0;
    }
    
    p_result[curve->num_digits*2 - 1] = (uint64_t)r01;
}

/* Computes p_result = p_left^2. */
static void vli_square(uint64_t *p_result, uint64_t *p_left, uECC_Curve curve)
{
    uint128_t r01 = 0;
    uint64_t r2 = 0;
    
    uint i, k;
    for(k=0; k < curve->num_digits*2 - 1; ++k)
    {
        uint l_min = (k < curve->num_digits ? 0 : (k + 1) - curve->num_digits);
        for(i=l_min; i<=k && i<=k-i; ++i)
        {
            uint128_t l_product = (uint128_t)p_left[i] * p_left[k-i];
            if(i < k-i)
            {
                r2 += l_product >> 127;
                l_product *= 2;
            }
            r01 += l_product;
            r2 += (r01 < l_product);
        }
        p_result[k] = (uint64_t)r01;
        r01 = (r01 >> 64) | (((uint128_t)r2) << 64);
        r2 = 0;
    }
    
    p_result[curve->num_digits*2 - 1] = (uint64_t)r01;
}

/* Computes p_result = (p_left + p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modAdd(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod, uECC_Curve curve)
{
    uint64_t l_carry = vli_add(p_result, p_left, p_right, curve);
    if(l_carry || vli_cmp(p_result, p_mod, curve) >= 0)
    { /* p_result > p_mod (p_result = p_mod + remainder), so subtract p_mod to get remainder. */
        vli_sub(p_result, p_result, p_mod, curve);
    }
}

/* Computes p_result = (p_left - p_right) % p_mod.
   Assumes that p_left < p_mod and p_right < p_mod, p_result != p_mod. */
static void vli_modSub(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod, uECC_Curve curve)
{
    uint64_t l_borrow = vli_sub(p_result, p_left, p_right, curve);
    if(l_borrow)
    { /* In this case, p_result == -diff == (max int) - diff.
         Since -x % d == d - x, we can get the correct result from p_result + p_mod (with overflow). */
        vli_add(p_result, p_result, p_mod, curve);
    }
}

#if ECC_CURVE == secp128r1

/* Computes p_result = p_product % curve_p.
   See algorithm 5 and 6 from http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[NUM_ECC_DIGITS];
    int l_carry;
    
    vli_set(p_result, p_product);
    
    l_tmp[0] = p_product[2];
    l_tmp[1] = (p_product[3] & 0x1FFFFFFFFull) | (p_product[2] << 33);
    l_carry = vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = (p_product[2] >> 31) | (p_product[3] << 33);
    l_tmp[1] = (p_product[3] >> 31) | ((p_product[2] & 0xFFFFFFFF80000000ull) << 2);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = (p_product[2] >> 62) | (p_product[3] << 2);
    l_tmp[1] = (p_product[3] >> 62) | ((p_product[2] & 0xC000000000000000ull) >> 29) | (p_product[3] << 35);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = (p_product[3] >> 29);
    l_tmp[1] = ((p_product[3] & 0xFFFFFFFFE0000000ull) << 4);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = (p_product[3] >> 60);
    l_tmp[1] = (p_product[3] & 0xFFFFFFFE00000000ull);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = 0;
    l_tmp[1] = ((p_product[3] & 0xF000000000000000ull) >> 27);
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    while(l_carry || vli_cmp(curve_p, p_result) != 1)
    {
        l_carry -= vli_sub(p_result, p_result, curve_p);
    }
}

#elif ECC_CURVE == secp192r1

/* Computes p_result = p_product % curve_p.
   See algorithm 5 and 6 from http://www.isys.uni-klu.ac.at/PDF/2001-0126-MT.pdf */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[NUM_ECC_DIGITS];
    int l_carry;
    
    vli_set(p_result, p_product);
    
    vli_set(l_tmp, &p_product[3]);
    l_carry = vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = 0;
    l_tmp[1] = p_product[3];
    l_tmp[2] = p_product[4];
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    l_tmp[0] = l_tmp[1] = p_product[5];
    l_tmp[2] = 0;
    l_carry += vli_add(p_result, p_result, l_tmp);
    
    while(l_carry || vli_cmp(curve_p, p_result) != 1)
    {
        l_carry -= vli_sub(p_result, p_result, curve_p);
    }
}

#elif ECC_CURVE == secp256r1

/* Computes p_result = p_product % curve_p
   from http://www.nsa.gov/ia/_files/nist-routines.pdf */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product, uECC_Curve curve)
{
    // uint64_t l_tmp[curve->num_digits];

    uint64_t *l_tmp = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    int l_carry;
    
    /* t */
    vli_set(p_result, p_product, curve);
    
    /* s1 */
    l_tmp[0] = 0;
    l_tmp[1] = p_product[5] & 0xffffffff00000000ull;
    l_tmp[2] = p_product[6];
    l_tmp[3] = p_product[7];
    l_carry = vli_lshift(l_tmp, l_tmp, 1, curve);
    l_carry += vli_add(p_result, p_result, l_tmp, curve);
    
    /* s2 */
    l_tmp[1] = p_product[6] << 32;
    l_tmp[2] = (p_product[6] >> 32) | (p_product[7] << 32);
    l_tmp[3] = p_product[7] >> 32;
    l_carry += vli_lshift(l_tmp, l_tmp, 1, curve);
    l_carry += vli_add(p_result, p_result, l_tmp, curve);
    
    /* s3 */
    l_tmp[0] = p_product[4];
    l_tmp[1] = p_product[5] & 0xffffffff;
    l_tmp[2] = 0;
    l_tmp[3] = p_product[7];
    l_carry += vli_add(p_result, p_result, l_tmp, curve);
    
    /* s4 */
    l_tmp[0] = (p_product[4] >> 32) | (p_product[5] << 32);
    l_tmp[1] = (p_product[5] >> 32) | (p_product[6] & 0xffffffff00000000ull);
    l_tmp[2] = p_product[7];
    l_tmp[3] = (p_product[6] >> 32) | (p_product[4] << 32);
    l_carry += vli_add(p_result, p_result, l_tmp, curve);
    
    /* d1 */
    l_tmp[0] = (p_product[5] >> 32) | (p_product[6] << 32);
    l_tmp[1] = (p_product[6] >> 32);
    l_tmp[2] = 0;
    l_tmp[3] = (p_product[4] & 0xffffffff) | (p_product[5] << 32);
    l_carry -= vli_sub(p_result, p_result, l_tmp, curve);
    
    /* d2 */
    l_tmp[0] = p_product[6];
    l_tmp[1] = p_product[7];
    l_tmp[2] = 0;
    l_tmp[3] = (p_product[4] >> 32) | (p_product[5] & 0xffffffff00000000ull);
    l_carry -= vli_sub(p_result, p_result, l_tmp, curve);
    
    /* d3 */
    l_tmp[0] = (p_product[6] >> 32) | (p_product[7] << 32);
    l_tmp[1] = (p_product[7] >> 32) | (p_product[4] << 32);
    l_tmp[2] = (p_product[4] >> 32) | (p_product[5] << 32);
    l_tmp[3] = (p_product[6] << 32);
    l_carry -= vli_sub(p_result, p_result, l_tmp, curve);
    
    /* d4 */
    l_tmp[0] = p_product[7];
    l_tmp[1] = p_product[4] & 0xffffffff00000000ull;
    l_tmp[2] = p_product[5];
    l_tmp[3] = p_product[6] & 0xffffffff00000000ull;
    l_carry -= vli_sub(p_result, p_result, l_tmp, curve);
    
    if(l_carry < 0)
    {
        do
        {
            l_carry += vli_add(p_result, p_result, curve->p, curve);
        } while(l_carry < 0);
    }
    else
    {
        while(l_carry || vli_cmp(curve->p, p_result, curve) != 1)
        {
            l_carry -= vli_sub(p_result, p_result, curve->p, curve);
        }
    }
}

#elif ECC_CURVE == secp384r1

static void omega_mult(uint64_t *p_result, uint64_t *p_right)
{
    uint64_t l_tmp[NUM_ECC_DIGITS];
    uint64_t l_carry, l_diff;
    
    /* Multiply by (2^128 + 2^96 - 2^32 + 1). */
    vli_set(p_result, p_right); /* 1 */
    l_carry = vli_lshift(l_tmp, p_right, 32);
    p_result[1 + NUM_ECC_DIGITS] = l_carry + vli_add(p_result + 1, p_result + 1, l_tmp); /* 2^96 + 1 */
    p_result[2 + NUM_ECC_DIGITS] = vli_add(p_result + 2, p_result + 2, p_right); /* 2^128 + 2^96 + 1 */
    l_carry += vli_sub(p_result, p_result, l_tmp); /* 2^128 + 2^96 - 2^32 + 1 */
    l_diff = p_result[NUM_ECC_DIGITS] - l_carry;
    if(l_diff > p_result[NUM_ECC_DIGITS])
    { /* Propagate borrow if necessary. */
        uint i;
        for(i = 1 + NUM_ECC_DIGITS; ; ++i)
        {
            --p_result[i];
            if(p_result[i] != (uint64_t)-1)
            {
                break;
            }
        }
    }
    p_result[NUM_ECC_DIGITS] = l_diff;
}

/* Computes p_result = p_product % curve_p
    see PDF "Comparing Elliptic Curve Cryptography and RSA on 8-bit CPUs"
    section "Curve-Specific Optimizations" */
static void vli_mmod_fast(uint64_t *p_result, uint64_t *p_product)
{
    uint64_t l_tmp[2*NUM_ECC_DIGITS];
     
    while(!vli_isZero(p_product + NUM_ECC_DIGITS)) /* While c1 != 0 */
    {
        uint64_t l_carry = 0;
        uint i;
        
        vli_clear(l_tmp);
        vli_clear(l_tmp + NUM_ECC_DIGITS);
        omega_mult(l_tmp, p_product + NUM_ECC_DIGITS); /* tmp = w * c1 */
        vli_clear(p_product + NUM_ECC_DIGITS); /* p = c0 */
        
        /* (c1, c0) = c0 + w * c1 */
        for(i=0; i<NUM_ECC_DIGITS+3; ++i)
        {
            uint64_t l_sum = p_product[i] + l_tmp[i] + l_carry;
            if(l_sum != p_product[i])
            {
                l_carry = (l_sum < p_product[i]);
            }
            p_product[i] = l_sum;
        }
    }
    
    while(vli_cmp(p_product, curve_p) > 0)
    {
        vli_sub(p_product, p_product, curve_p);
    }
    vli_set(p_result, p_product);
}

#endif

/* Computes p_result = (p_left * p_right) % curve_p. */
static void vli_modMult_fast(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uECC_Curve curve)
{
    // uint64_t l_product[2 * curve->num_digits];
    uint64_t *l_product = (uint64_t *)malloc(curve->num_digits * 2 * sizeof(uint64_t));
    vli_mult(l_product, p_left, p_right, curve);
    vli_mmod_fast(p_result, l_product, curve);
}

/* Computes p_result = p_left^2 % curve_p. */
static void vli_modSquare_fast(uint64_t *p_result, uint64_t *p_left, uECC_Curve curve)
{
    // uint64_t l_product[2 * curve->num_digits];
    uint64_t *l_product = (uint64_t *)malloc(curve->num_digits * 2 * sizeof(uint64_t));
    vli_square(l_product, p_left, curve);
    vli_mmod_fast(p_result, l_product, curve);
}

#define EVEN(vli) (!(vli[0] & 1))
/* Computes p_result = (1 / p_input) % p_mod. All VLIs are the same size.
   See "From Euclid's GCD to Montgomery Multiplication to the Great Divide"
   https://labs.oracle.com/techrep/2001/smli_tr-2001-95.pdf */
static void vli_modInv(uint64_t *p_result, uint64_t *p_input, uint64_t *p_mod, uECC_Curve curve)
{
    // uint64_t a[curve->num_digits], b[curve->num_digits], u[curve->num_digits], v[curve->num_digits];

    uint64_t *a = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *b = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *u = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *v = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t l_carry;
    int l_cmpResult;
    
    if(vli_isZero(p_input, curve))
    {
        vli_clear(p_result, curve);
        return;
    }

    vli_set(a, p_input, curve);
    vli_set(b, p_mod, curve);
    vli_clear(u, curve);
    u[0] = 1;
    vli_clear(v, curve);
    
    while((l_cmpResult = vli_cmp(a, b, curve)) != 0)
    {
        l_carry = 0;
        if(EVEN(a))
        {
            vli_rshift1(a, curve);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod, curve);
            }
            vli_rshift1(u, curve);
            if(l_carry)
            {
                u[curve->num_digits-1] |= 0x8000000000000000ull;
            }
        }
        else if(EVEN(b))
        {
            vli_rshift1(b, curve);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod, curve);
            }
            vli_rshift1(v, curve);
            if(l_carry)
            {
                v[curve->num_digits-1] |= 0x8000000000000000ull;
            }
        }
        else if(l_cmpResult > 0)
        {
            vli_sub(a, a, b, curve);
            vli_rshift1(a, curve);
            if(vli_cmp(u, v, curve) < 0)
            {
                vli_add(u, u, p_mod, curve);
            }
            vli_sub(u, u, v, curve);
            if(!EVEN(u))
            {
                l_carry = vli_add(u, u, p_mod, curve);
            }
            vli_rshift1(u, curve);
            if(l_carry)
            {
                u[curve->num_digits-1] |= 0x8000000000000000ull;
            }
        }
        else
        {
            vli_sub(b, b, a, curve);
            vli_rshift1(b, curve);
            if(vli_cmp(v, u, curve) < 0)
            {
                vli_add(v, v, p_mod, curve);
            }
            vli_sub(v, v, u, curve);
            if(!EVEN(v))
            {
                l_carry = vli_add(v, v, p_mod, curve);
            }
            vli_rshift1(v, curve);
            if(l_carry)
            {
                v[curve->num_digits-1] |= 0x8000000000000000ull;
            }
        }
    }
    
    vli_set(p_result, u, curve);
}

/* ------ Point operations ------ */

/* Returns 1 if p_point is the point at infinity, 0 otherwise. */
static int EccPoint_isZero(EccPoint *p_point, uECC_Curve curve)
{
    return (vli_isZero(p_point->x, curve) && vli_isZero(p_point->y, curve));
}

/* Point multiplication algorithm using Montgomery's ladder with co-Z coordinates.
From http://eprint.iacr.org/2011/338.pdf
*/

/* Double in place */
static void EccPoint_double_jacobian(uint64_t *X1, uint64_t *Y1, uint64_t *Z1, uECC_Curve curve)
{
    /* t1 = X, t2 = Y, t3 = Z */
    // uint64_t t4[curve->num_digits];
    // uint64_t t5[curve->num_digits];
    
    uint64_t *t4 = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *t5 = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    if(vli_isZero(Z1, curve))
    {
        return;
    }
    
    vli_modSquare_fast(t4, Y1, curve);   /* t4 = y1^2 */
    vli_modMult_fast(t5, X1, t4, curve); /* t5 = x1*y1^2 = A */
    vli_modSquare_fast(t4, t4, curve);   /* t4 = y1^4 */
    vli_modMult_fast(Y1, Y1, Z1, curve); /* t2 = y1*z1 = z3 */
    vli_modSquare_fast(Z1, Z1, curve);   /* t3 = z1^2 */
    
    vli_modAdd(X1, X1, Z1, curve->p, curve); /* t1 = x1 + z1^2 */
    vli_modAdd(Z1, Z1, Z1, curve->p, curve); /* t3 = 2*z1^2 */
    vli_modSub(Z1, X1, Z1, curve->p, curve); /* t3 = x1 - z1^2 */
    vli_modMult_fast(X1, X1, Z1, curve);    /* t1 = x1^2 - z1^4 */
    
    vli_modAdd(Z1, X1, X1, curve->p, curve); /* t3 = 2*(x1^2 - z1^4) */
    vli_modAdd(X1, X1, Z1, curve->p, curve); /* t1 = 3*(x1^2 - z1^4) */
    if(vli_testBit(X1, 0))
    {
        uint64_t l_carry = vli_add(X1, X1, curve->p, curve);
        vli_rshift1(X1, curve);
        X1[curve->num_digits-1] |= l_carry << 63;
    }
    else
    {
        vli_rshift1(X1, curve);
    }
    /* t1 = 3/2*(x1^2 - z1^4) = B */
    
    vli_modSquare_fast(Z1, X1, curve);      /* t3 = B^2 */
    vli_modSub(Z1, Z1, t5, curve->p, curve); /* t3 = B^2 - A */
    vli_modSub(Z1, Z1, t5, curve->p, curve); /* t3 = B^2 - 2A = x3 */
    vli_modSub(t5, t5, Z1, curve->p, curve); /* t5 = A - x3 */
    vli_modMult_fast(X1, X1, t5, curve);    /* t1 = B * (A - x3) */
    vli_modSub(t4, X1, t4, curve->p, curve); /* t4 = B * (A - x3) - y1^4 = y3 */
    
    vli_set(X1, Z1, curve);
    vli_set(Z1, Y1, curve);
    vli_set(Y1, t4, curve);
}

/* Modify (x1, y1) => (x1 * z^2, y1 * z^3) */
static void apply_z(uint64_t *X1, uint64_t *Y1, uint64_t *Z, uECC_Curve curve)
{
    // uint64_t t1[curve->num_digits];

    uint64_t *t1 = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    vli_modSquare_fast(t1, Z, curve);    /* z^2 */
    vli_modMult_fast(X1, X1, t1, curve); /* x1 * z^2 */
    vli_modMult_fast(t1, t1, Z, curve);  /* z^3 */
    vli_modMult_fast(Y1, Y1, t1, curve); /* y1 * z^3 */
}

/* P = (x1, y1) => 2P, (x2, y2) => P' */
static void XYcZ_initial_double(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2, uint64_t *p_initialZ, uECC_Curve curve)
{
    uint64_t *z = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    // uint64_t z[curve->num_digits];
    
    vli_set(X2, X1, curve);
    vli_set(Y2, Y1, curve);
    
    vli_clear(z, curve);
    z[0] = 1;
    if(p_initialZ)
    {
        vli_set(z, p_initialZ, curve);
    }

    apply_z(X1, Y1, z, curve);
    
    EccPoint_double_jacobian(X1, Y1, z, curve);
    
    apply_z(X2, Y2, z, curve);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P' = (x1', y1', Z3), P + Q = (x3, y3, Z3)
   or P => P', Q => P + Q
*/
static void XYcZ_add(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2, uECC_Curve curve)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    // uint64_t t5[NUM_ECC_DIGITS];
    uint64_t *t5 = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    
    vli_modSub(t5, X2, X1, curve->p, curve); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5, curve);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5, curve);    /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5, curve);    /* t3 = x2*A = C */
    vli_modSub(Y2, Y2, Y1, curve->p, curve); /* t4 = y2 - y1 */
    vli_modSquare_fast(t5, Y2, curve);      /* t5 = (y2 - y1)^2 = D */
    
    vli_modSub(t5, t5, X1, curve->p, curve); /* t5 = D - B */
    vli_modSub(t5, t5, X2, curve->p, curve); /* t5 = D - B - C = x3 */
    vli_modSub(X2, X2, X1, curve->p, curve); /* t3 = C - B */
    vli_modMult_fast(Y1, Y1, X2, curve);    /* t2 = y1*(C - B) */
    vli_modSub(X2, X1, t5, curve->p, curve); /* t3 = B - x3 */
    vli_modMult_fast(Y2, Y2, X2, curve);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub(Y2, Y2, Y1, curve->p, curve); /* t4 = y3 */
    
    vli_set(X2, t5, curve);
}

/* Input P = (x1, y1, Z), Q = (x2, y2, Z)
   Output P + Q = (x3, y3, Z3), P - Q = (x3', y3', Z3)
   or P => P - Q, Q => P + Q
*/
static void XYcZ_addC(uint64_t *X1, uint64_t *Y1, uint64_t *X2, uint64_t *Y2, uECC_Curve curve)
{
    /* t1 = X1, t2 = Y1, t3 = X2, t4 = Y2 */
    // uint64_t t5[curve->num_digits];
    // uint64_t t6[curve->num_digits];
    // uint64_t t7[curve->num_digits];

    uint64_t *t5 = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *t6 = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *t7 = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    
    vli_modSub(t5, X2, X1, curve->p, curve); /* t5 = x2 - x1 */
    vli_modSquare_fast(t5, t5, curve);      /* t5 = (x2 - x1)^2 = A */
    vli_modMult_fast(X1, X1, t5, curve);    /* t1 = x1*A = B */
    vli_modMult_fast(X2, X2, t5, curve);    /* t3 = x2*A = C */
    vli_modAdd(t5, Y2, Y1, curve->p, curve); /* t4 = y2 + y1 */
    vli_modSub(Y2, Y2, Y1, curve->p, curve); /* t4 = y2 - y1 */

    vli_modSub(t6, X2, X1, curve->p, curve); /* t6 = C - B */
    vli_modMult_fast(Y1, Y1, t6, curve);    /* t2 = y1 * (C - B) */
    vli_modAdd(t6, X1, X2, curve->p, curve); /* t6 = B + C */
    vli_modSquare_fast(X2, Y2, curve);      /* t3 = (y2 - y1)^2 */
    vli_modSub(X2, X2, t6, curve->p, curve); /* t3 = x3 */
    
    vli_modSub(t7, X1, X2, curve->p, curve); /* t7 = B - x3 */
    vli_modMult_fast(Y2, Y2, t7, curve);    /* t4 = (y2 - y1)*(B - x3) */
    vli_modSub(Y2, Y2, Y1, curve->p, curve); /* t4 = y3 */
    
    vli_modSquare_fast(t7, t5, curve);      /* t7 = (y2 + y1)^2 = F */
    vli_modSub(t7, t7, t6, curve->p, curve); /* t7 = x3' */
    vli_modSub(t6, t7, X1, curve->p, curve); /* t6 = x3' - B */
    vli_modMult_fast(t6, t6, t5, curve);    /* t6 = (y2 + y1)*(x3' - B) */
    vli_modSub(Y1, t6, Y1, curve->p, curve); /* t2 = y3' */
    
    vli_set(X1, t7, curve);
}

static void EccPoint_mult(EccPoint *p_result, EccPoint *p_point, uint64_t *p_scalar, uint64_t *p_initialZ, uECC_Curve curve)
{
    /* R0 and R1 */
    uint64_t *Rx = (uint64_t *)malloc(curve->num_digits * 2 * sizeof(uint64_t));
    uint64_t *Ry = (uint64_t *)malloc(curve->num_digits * 2 * sizeof(uint64_t));
    uint64_t *z = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));

    // uint64_t Rx[curve->num_digits*2];
    // uint64_t Ry[curve->num_digits*2];
    // uint64_t z[curve->num_digits];
    int i, nb;
    
    // printf("Set Gx Gy\n");
    vli_set(&Rx[1], p_point->x, curve);
    vli_set(&Ry[1], p_point->y, curve);

    // printf("Start XYcZ_initial_double\n");
    XYcZ_initial_double(&Rx[1], &Ry[1], &Rx[0], &Ry[0], p_initialZ, curve);

    // printf("Start XYcZ_addC\n");
    for(i = vli_numBits(p_scalar, curve) - 2; i > 0; --i)
    {
        nb = !vli_testBit(p_scalar, i);
        XYcZ_addC(&Rx[1-nb], &Ry[1-nb], &Rx[nb], &Ry[nb], curve);
        XYcZ_add(&Rx[nb], &Ry[nb], &Rx[1-nb], &Ry[1-nb], curve);
    }

    nb = !vli_testBit(p_scalar, 0);
    XYcZ_addC(&Rx[1-nb], &Ry[1-nb], &Rx[nb], &Ry[nb], curve);
    
    /* Find final 1/Z value. */
    vli_modSub(z, &Rx[1], &Rx[0], curve->p, curve); /* X1 - X0 */
    vli_modMult_fast(z, z, &Ry[1-nb], curve);     /* Yb * (X1 - X0) */
    vli_modMult_fast(z, z, p_point->x, curve);   /* xP * Yb * (X1 - X0) */
    vli_modInv(z, z, curve->p, curve);            /* 1 / (xP * Yb * (X1 - X0)) */
    vli_modMult_fast(z, z, p_point->y, curve);   /* yP / (xP * Yb * (X1 - X0)) */
    vli_modMult_fast(z, z, &Rx[1-nb], curve);     /* Xb * yP / (xP * Yb * (X1 - X0)) */
    /* End 1/Z calculation */

    XYcZ_add(&Rx[nb], &Ry[nb], &Rx[1-nb], &Ry[1-nb], curve);
    
    apply_z(&Rx[0], &Ry[0], z, curve);
    
    vli_set(p_result->x, &Rx[0], curve);
    vli_set(p_result->y, &Ry[0], curve);
}

static void ecc_bytes2native(uint64_t *p_native, const uint8_t *p_bytes, uECC_Curve curve)
{
    unsigned i;
    for(i=0; i<curve->num_digits; ++i)
    {
        const uint8_t *p_digit = p_bytes + 8 * (curve->num_digits - 1 - i);
        p_native[i] = ((uint64_t)p_digit[0] << 56) | ((uint64_t)p_digit[1] << 48) | ((uint64_t)p_digit[2] << 40) | ((uint64_t)p_digit[3] << 32) |
            ((uint64_t)p_digit[4] << 24) | ((uint64_t)p_digit[5] << 16) | ((uint64_t)p_digit[6] << 8) | (uint64_t)p_digit[7];
    }
}

// static void ecc_native2bytes(uint8_t p_bytes[ECC_BYTES], const uint64_t p_native[NUM_ECC_DIGITS], uECC_Curve curve)
static void ecc_native2bytes(uint8_t *p_bytes, const uint64_t *p_native, uECC_Curve curve)
{
    unsigned i;
    for(i=0; i<curve->num_digits; ++i)
    {
        uint8_t *p_digit = p_bytes + 8 * (curve->num_digits - 1 - i);
        p_digit[0] = p_native[i] >> 56;
        p_digit[1] = p_native[i] >> 48;
        p_digit[2] = p_native[i] >> 40;
        p_digit[3] = p_native[i] >> 32;
        p_digit[4] = p_native[i] >> 24;
        p_digit[5] = p_native[i] >> 16;
        p_digit[6] = p_native[i] >> 8;
        p_digit[7] = p_native[i];
    }
}

/* Compute a = sqrt(a) (mod curve_p). */
static void mod_sqrt(uint64_t *a, uECC_Curve curve)
{
    unsigned i;
    uint64_t *p1 = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *l_result = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    memset(p1, 1, curve->num_digits * sizeof(uint64_t));
    memset(l_result, 1, curve->num_digits * sizeof(uint64_t));
    // uint64_t p1[curve->num_digits] = {1};
    // uint64_t l_result[curve->num_digits] = {1};
    
    /* Since curve_p == 3 (mod 4) for all supported curves, we can
       compute sqrt(a) = a^((curve_p + 1) / 4) (mod curve_p). */
    vli_add(p1, curve->p, p1, curve); /* p1 = curve_p + 1 */
    for(i = vli_numBits(p1, curve) - 1; i > 1; --i)
    {
        vli_modSquare_fast(l_result, l_result, curve);
        if(vli_testBit(p1, i))
        {
            vli_modMult_fast(l_result, l_result, a, curve);
        }
    }
    vli_set(a, l_result, curve);
}

static void ecc_point_decompress(EccPoint *p_point, const uint8_t *p_compressed, uECC_Curve curve)
{
    uint64_t *_3 = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    _3[0]=3;
    // uint64_t _3[NUM_ECC_DIGITS] = {3}; /* -a = 3 */
    ecc_bytes2native(p_point->x, p_compressed+1, curve);
    
    vli_modSquare_fast(p_point->y, p_point->x, curve); /* y = x^2 */
    vli_modSub(p_point->y, p_point->y, _3, curve->p, curve); /* y = x^2 - 3 */
    vli_modMult_fast(p_point->y, p_point->y, p_point->x, curve); /* y = x^3 - 3x */
    vli_modAdd(p_point->y, p_point->y, curve->b, curve->p, curve); /* y = x^3 - 3x + b */
    
    mod_sqrt(p_point->y, curve);
    
    if((p_point->y[0] & 0x01) != (p_compressed[0] & 0x01))
    {
        vli_sub(p_point->y, curve->p, p_point->y, curve);
    }
}

int ecc_make_key(uint8_t *p_publicKey, uint8_t *p_privateKey, curve_type curve_type)
{
    uECC_Curve curve;
    switch (curve_type)
    {
    case P192:
        curve = p192;
        break;
    case P256:
        curve = p256;
        break;
    default:
        break;
    }
    // uint64_t* l_private;
    uint64_t *l_private = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    EccPoint l_public;
    unsigned l_tries = 0;
    do
    {
        if(!getRandomNumber(l_private, curve) || (l_tries++ >= MAX_TRIES))
        {
            return 0;
        }
        if(vli_isZero(l_private, curve))
        {
            continue;
        }
    
        /* Make sure the private key is in the range [1, n-1].
           For the supported curves, n is always large enough that we only need to subtract once at most. */
        if(vli_cmp(curve->n, l_private, curve) != 1)
        {
            vli_sub(l_private, l_private, curve->n, curve);
        }


        EccPoint_mult(&l_public, &curve->G, l_private, NULL, curve);
    } while(EccPoint_isZero(&l_public, curve));
    
    ecc_native2bytes(p_privateKey, l_private, curve);
    ecc_native2bytes(p_publicKey + 1, l_public.x, curve);
    p_publicKey[0] = 2 + (l_public.y[0] & 0x01);
    return 1;
}

int ecdh_shared_secret(const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_privateKey[ECC_BYTES], uint8_t p_secret[ECC_BYTES], uECC_Curve curve)
{
    EccPoint l_public;
    // uint64_t l_private[curve->num_digits];
    // uint64_t l_random[curve->num_digits];

    uint64_t *l_private = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *l_random = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    
    if(!getRandomNumber(l_random, curve))
    {
        return 0;
    }
    
    ecc_point_decompress(&l_public, p_publicKey, curve);
    ecc_bytes2native(l_private, p_privateKey, curve);
    
    EccPoint l_product;
    EccPoint_mult(&l_product, &l_public, l_private, l_random, curve);
    
    ecc_native2bytes(p_secret, l_product.x, curve);
    
    return !EccPoint_isZero(&l_product, curve);
}

/* -------- ECDSA code -------- */

/* Computes p_result = (p_left * p_right) % p_mod. */
static void vli_modMult(uint64_t *p_result, uint64_t *p_left, uint64_t *p_right, uint64_t *p_mod, uECC_Curve curve)
{
    uint64_t *l_product = (uint64_t *)malloc(curve->num_digits * 2 * sizeof(uint64_t));
    uint64_t *l_modMultiple = (uint64_t *)malloc(curve->num_digits * 2 * sizeof(uint64_t));

    // uint64_t l_product[2 * curve->num_digits];
    // uint64_t l_modMultiple[2 * curve->num_digits];
    uint l_digitShift, l_bitShift;
    uint l_productBits;
    uint l_modBits = vli_numBits(p_mod, curve);
    
    vli_mult(l_product, p_left, p_right, curve);
    l_productBits = vli_numBits(l_product + curve->num_digits, curve);
    if(l_productBits)
    {
        l_productBits += curve->num_digits * 64;
    }
    else
    {
        l_productBits = vli_numBits(l_product, curve);
    }
    
    if(l_productBits < l_modBits)
    { /* l_product < p_mod. */
        vli_set(p_result, l_product, curve);
        return;
    }
    
    /* Shift p_mod by (l_leftBits - l_modBits). This multiplies p_mod by the largest
       power of two possible while still resulting in a number less than p_left. */
    vli_clear(l_modMultiple, curve);
    vli_clear(l_modMultiple + curve->num_digits, curve);
    l_digitShift = (l_productBits - l_modBits) / 64;
    l_bitShift = (l_productBits - l_modBits) % 64;
    if(l_bitShift)
    {
        l_modMultiple[l_digitShift + curve->num_digits] = vli_lshift(l_modMultiple + l_digitShift, p_mod, l_bitShift, curve);
    }
    else
    {
        vli_set(l_modMultiple + l_digitShift, p_mod, curve);
    }

    /* Subtract all multiples of p_mod to get the remainder. */
    vli_clear(p_result, curve);
    p_result[0] = 1; /* Use p_result as a temp var to store 1 (for subtraction) */
    while(l_productBits > curve->num_digits * 64 || vli_cmp(l_modMultiple, p_mod, curve) >= 0)
    {
        int l_cmp = vli_cmp(l_modMultiple + curve->num_digits, l_product + curve->num_digits, curve);
        if(l_cmp < 0 || (l_cmp == 0 && vli_cmp(l_modMultiple, l_product, curve) <= 0))
        {
            if(vli_sub(l_product, l_product, l_modMultiple, curve))
            { /* borrow */
                vli_sub(l_product + curve->num_digits, l_product + curve->num_digits, p_result, curve);
            }
            vli_sub(l_product + curve->num_digits, l_product + curve->num_digits, l_modMultiple + curve->num_digits, curve);
        }
        uint64_t l_carry = (l_modMultiple[curve->num_digits] & 0x01) << 63;
        vli_rshift1(l_modMultiple + curve->num_digits, curve);
        vli_rshift1(l_modMultiple, curve);
        l_modMultiple[curve->num_digits-1] |= l_carry;
        
        --l_productBits;
    }
    vli_set(p_result, l_product, curve);
}

static uint umax(uint a, uint b)
{
    return (a > b ? a : b);
}

int ecdsa_sign(const uint8_t p_privateKey[ECC_BYTES], const uint8_t p_hash[ECC_BYTES], uint8_t p_signature[ECC_BYTES*2], curve_type curve_type)
{
    uECC_Curve curve;
    switch (curve_type)
    {
    case P192:
        curve = p192;
        break;
    case P256:
        curve = p256;
        break;
    default:
        break;
    }
    // uint64_t k[curve->num_digits];
    // uint64_t l_tmp[curve->num_digits];
    // uint64_t l_s[curve->num_digits];
    uint64_t *k = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *l_tmp = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *l_s = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    EccPoint p;
    unsigned l_tries = 0;
    
    do
    {
        if(!getRandomNumber(k, curve) || (l_tries++ >= MAX_TRIES))
        {
            return 0;
        }
        if(vli_isZero(k, curve))
        {
            continue;
        }
    
        if(vli_cmp(curve->n, k, curve) != 1)
        {
            vli_sub(k, k, curve->n, curve);
        }
    
        /* tmp = k * G */
        EccPoint_mult(&p, &curve->G, k, NULL, curve);
    
        /* r = x1 (mod n) */
        if(vli_cmp(curve->n, p.x, curve) != 1)
        {
            vli_sub(p.x, p.x, curve->n, curve);
        }
    } while(vli_isZero(p.x, curve));

    ecc_native2bytes(p_signature, p.x, curve);
    
    ecc_bytes2native(l_tmp, p_privateKey, curve);
    vli_modMult(l_s, p.x, l_tmp, curve->n, curve); /* s = r*d */
    ecc_bytes2native(l_tmp, p_hash, curve);
    vli_modAdd(l_s, l_tmp, l_s, curve->n, curve); /* s = e + r*d */
    vli_modInv(k, k, curve->n, curve); /* k = 1 / k */
    vli_modMult(l_s, l_s, k, curve->n, curve); /* s = (e + r*d) / k */
    ecc_native2bytes(p_signature + curve->num_words, l_s, curve);
    
    return 1;
}

int ecdsa_verify(const uint8_t p_publicKey[ECC_BYTES+1], const uint8_t p_hash[ECC_BYTES], const uint8_t p_signature[ECC_BYTES*2], curve_type curve_type)
{
    uECC_Curve curve;
    switch (curve_type)
    {
    case P192:
        curve = p192;
        break;
    case P256:
        curve = p256;
        break;
    default:
        break;
    }
    uint64_t *u1 = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *u2 = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *z = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *rx = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *ry = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *tx = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *ty = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *tz = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *l_r = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));
    uint64_t *l_s = (uint64_t *)malloc(curve->num_digits * sizeof(uint64_t));

    // uint64_t u1[curve->num_digits], u2[curve->num_digits];
    // uint64_t z[curve->num_digits];
    EccPoint l_public, l_sum;
    // uint64_t rx[curve->num_digits];
    // uint64_t ry[curve->num_digits];
    // uint64_t tx[curve->num_digits];
    // uint64_t ty[curve->num_digits];
    // uint64_t tz[curve->num_digits];
    
    // uint64_t l_r[curve->num_digits], l_s[curve->num_digits];
    
    ecc_point_decompress(&l_public, p_publicKey, curve);
    ecc_bytes2native(l_r, p_signature, curve);
    ecc_bytes2native(l_s, p_signature + curve->num_words, curve);
    
    if(vli_isZero(l_r, curve) || vli_isZero(l_s, curve))
    { /* r, s must not be 0. */
        return 0;
    }
    
    if(vli_cmp(curve->n, l_r, curve) != 1 || vli_cmp(curve->n, l_s, curve) != 1)
    { /* r, s must be < n. */
        return 0;
    }

    /* Calculate u1 and u2. */
    vli_modInv(z, l_s, curve->n, curve); /* Z = s^-1 */
    ecc_bytes2native(u1, p_hash, curve);
    vli_modMult(u1, u1, z, curve->n, curve); /* u1 = e/s */
    vli_modMult(u2, l_r, z, curve->n, curve); /* u2 = r/s */
    
    /* Calculate l_sum = G + Q. */
    vli_set(l_sum.x, l_public.x, curve);
    vli_set(l_sum.y, l_public.y, curve);
    vli_set(tx, curve->G.x, curve);
    vli_set(ty, curve->G.y, curve);
    vli_modSub(z, l_sum.x, tx, curve->p, curve); /* Z = x2 - x1 */
    XYcZ_add(tx, ty, l_sum.x, l_sum.y, curve);
    vli_modInv(z, z, curve->p, curve); /* Z = 1/Z */
    apply_z(l_sum.x, l_sum.y, z, curve);
    
    /* Use Shamir's trick to calculate u1*G + u2*Q */
    EccPoint *l_points[4] = {NULL, &curve->G, &l_public, &l_sum};
    uint l_numBits = umax(vli_numBits(u1, curve), vli_numBits(u2, curve));
    
    EccPoint *l_point = l_points[(!!vli_testBit(u1, l_numBits-1)) | ((!!vli_testBit(u2, l_numBits-1)) << 1)];
    vli_set(rx, l_point->x, curve);
    vli_set(ry, l_point->y, curve);
    vli_clear(z, curve);
    z[0] = 1;

    int i;
    for(i = l_numBits - 2; i >= 0; --i)
    {
        EccPoint_double_jacobian(rx, ry, z, curve);
        
        int l_index = (!!vli_testBit(u1, i)) | ((!!vli_testBit(u2, i)) << 1);
        EccPoint *l_point = l_points[l_index];
        if(l_point)
        {
            vli_set(tx, l_point->x, curve);
            vli_set(ty, l_point->y, curve);
            apply_z(tx, ty, z, curve);
            vli_modSub(tz, rx, tx, curve->p, curve); /* Z = x2 - x1 */
            XYcZ_add(tx, ty, rx, ry, curve);
            vli_modMult_fast(z, z, tz, curve);
        }
    }

    vli_modInv(z, z, curve->p, curve); /* Z = 1/Z */
    apply_z(rx, ry, z, curve);
    
    /* v = x1 (mod n) */
    if(vli_cmp(curve->n, rx, curve) != 1)
    {
        vli_sub(rx, rx, curve->n, curve);
    }

    /* Accept only if v == r. */
    return (vli_cmp(rx, l_r, curve) == 0);
}
