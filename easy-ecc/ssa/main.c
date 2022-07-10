#include "ecc.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <memory.h>
#include "sha256.h"

#define TC_PRINT(fmt, ...) PRINT_DATA(fmt, ##__VA_ARGS__)
#define PRINT_DATA(fmt, ...) printf(fmt, ##__VA_ARGS__)

// static struct uECC_Curve p192, p256;

int main(){
    // uint8_t p_192_publicKey[24+1] = {0};
    // uint8_t p_192_privateKey[24] = {0};
    uint8_t ret;

    // ret = ecc_make_key(p_192_publicKey, p_192_privateKey, P192);

    // printf("P192 make_key ECC_BYTES 24\n");
    // printf("ret: %u\n", ret);
    // printf("PubKey: \n");
    // for(int i = 0; i<48;i++){ TC_PRINT("%03u ", p_192_publicKey[i]); }

    // printf("\nPrvKey: \n");
    // for(int i = 0; i<24;i++){ TC_PRINT("%03u ", p_192_privateKey[i]); }

    uint8_t p_256_publicKey[32+1] = {0};
    uint8_t p_256_privateKey[32] = {0};

    ret = ecc_make_key(p_256_publicKey, p_256_privateKey, P256);
    if (ret == 0) { printf("ecc_make_key failure\n");}

    // printf("\n\nP256 make_key ECC_BYTES 32\n");
    // printf("ret: %u\n", ret);
    // printf("PubKey: \n");
    // for(int i = 0; i<33;i++){ TC_PRINT("%03u ", p_256_publicKey[i]); }

    // printf("\nPrvKey: \n");
    // for(int i = 0; i<32;i++){ TC_PRINT("%03u ", p_256_privateKey[i]); }
    // printf("\n");



    // ECDSA P256
    uint8_t hash[32]={0x02};
    uint8_t signature[32*2]={0};

    ret = ecdsa_sign(p_256_privateKey, hash, signature, P256);
    if (ret == 0) { printf("ecdsa_sign failure\n"); }

    // printf("hash\n");
    // for(int i = 0; i<32; i++){ TC_PRINT("%03u ", hash[i]); }
    // printf("\np256_signature\n");
    // for(int i = 0; i<64; i++){ TC_PRINT("%03u ", signature[i]); }
    // printf("ret: %u\n", ret);

    ret = ecdsa_verify(p_256_publicKey, hash, signature, P256);
    if (ret == 0) { printf("verify failure\n"); }

    // printf("ret: %u\n", ret);



    return 0;
}






    
    // // SHA 256
    // BYTE text3[] = {"aaaaaaaaaa"}, buf[32];
	// SHA256_CTX ctx;

	// sha256_init(&ctx);
	// sha256_update(&ctx, text3, 11);
	// sha256_final(&ctx, buf);
    // printf("\n");
    // for(int i = 0; i<32; i++){ TC_PRINT("%03u ", buf[i]); }
    // printf("\n");