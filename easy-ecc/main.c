#include "ecc.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define TC_PRINT(fmt, ...) PRINT_DATA(fmt, ##__VA_ARGS__)
#define PRINT_DATA(fmt, ...) printf(fmt, ##__VA_ARGS__)

int main()
{
    // ECC_BYTES = secp192r1;
    int ct = secp256r1;
    uint8_t public_key_256[ct + 1];
    uint8_t private_key_256[ct];
    uint32_t i = 0;
    int ret = 0;
    ret = set_CT(P256);
    if (ret == 0) {
        printf("set_CT failure\n");
        return 0;
    }
        
    ret = ecc_make_key(public_key_256, private_key_256);
    if (ret == 0) { printf("ecc_make_key failure\n"); }
    printf("##############P-256 public key################\n");
    for (i = 0;i < ct + 1;i++) { TC_PRINT("%02x ", public_key_256[i]); }
    printf("\n##############P-256 private key###############\n");
    for (i = 0;i < ct;i++) { TC_PRINT("%02x ", private_key_256[i]); }
    printf("\n==============================================\n");
    
    ct = secp192r1;
    uint8_t public_key_192[ct + 1];
    uint8_t private_key_192[ct];
    ret = set_CT(P192);
    if (ret == 0) { printf("set_CT failure\n"); } 
    
    ret = ecc_make_key(public_key_192, private_key_192);
    if (ret == 0) {
        printf("ecc_make_key failure\n");
        return 0;
    }
    printf("##############P-192 public key################\n");
    for (i = 0;i < ct + 1;i++) { TC_PRINT("%02x ", public_key_192[i]); }
    printf("\n##############P-192 private key###############\n");
    for (i = 0;i < ct;i++) { TC_PRINT("%02x ", private_key_192[i]); }
    printf("\n==============================================\n");
    
    ct = secp256r1;
    uint8_t signature_256[ct * 2];
    uint8_t hash[ct];
    hash[0] = 0x2;
    printf("P-256 ecdsa_sign\n");
    ret = set_CT(P256);
    if (ret == 0) { printf("set_CT failure\n"); } 
    ret = ecdsa_sign(private_key_256, hash, signature_256);
    if (ret == 0) { printf("ecdsa_sign failure\n"); }
    for (i = 0;i < ct*2;i++) { TC_PRINT("%02x ", signature_256[i]); }

    printf("\nP-256 verify\n");
    ret = ecdsa_verify(public_key_256, hash, signature_256);
    if (ret == 1) { printf("verify passed\n"); } 
    else { printf("verify failed\n"); }
    printf("\n==============================================\n");
    
    ct = secp192r1;
    uint8_t remote_public_key_192[ct + 1];
    uint8_t remote_private_key_192[ct];
    ret = set_CT(P192);
    if (ret == 0) { printf("set_CT failure\n"); } 
    
    ret = ecc_make_key(remote_public_key_192, remote_private_key_192);
    if (ret == 0) {
        printf("ecc_make_key failure\n");
        return 0;
    }
    printf("##############P-192 public key################\n");
    for (i = 0;i < ct + 1;i++) { TC_PRINT("%02x ", remote_public_key_192[i]); }
    printf("\n##############P-192 private key###############\n");
    for (i = 0;i < ct;i++) { TC_PRINT("%02x ", remote_private_key_192[i]); }


    printf("\nP-192 ecdh\n");
    uint8_t local_secret[ct], remote_secret[ct];
    printf("################# P-192 local###################\n");
    ret = ecdh_shared_secret(remote_public_key_192, private_key_192, local_secret);
    for (i = 0;i < ct;i++) { TC_PRINT("%02x ", local_secret[i]); }
    printf("\n################# P-192 remote###################\n");
    ret = ecdh_shared_secret(public_key_192, remote_private_key_192, remote_secret);
    for (i = 0;i < ct;i++) { TC_PRINT("%02x ", remote_secret[i]); }
    printf("\n==============================================\n");


    return 0;
}