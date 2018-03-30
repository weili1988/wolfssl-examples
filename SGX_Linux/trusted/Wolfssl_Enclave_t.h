#ifndef WOLFSSL_ENCLAVE_T_H__
#define WOLFSSL_ENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */

#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfcrypt/test/test.h"
#include "wolfcrypt/benchmark/benchmark.h"

#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif


int wc_test(void* args);
int wc_benchmark_test(void* args);
int enc_wolfSSL_Init();
void enc_wolfSSL_Debugging_ON();
void enc_wolfSSL_Debugging_OFF();
WOLFSSL_METHOD* enc_wolfTLSv1_2_client_method();
WOLFSSL_METHOD* enc_wolfTLSv1_2_server_method();
WOLFSSL_CTX* enc_wolfSSL_CTX_new(WOLFSSL_METHOD* method);
int enc_wolfSSL_CTX_use_PrivateKey_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_load_verify_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_use_certificate_chain_buffer_format(WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_use_certificate_buffer(WOLFSSL_CTX* ctx, const unsigned char* buf, long int sz, int type);
int enc_wolfSSL_CTX_set_cipher_list(WOLFSSL_CTX* ctx, const char* list);
WOLFSSL* enc_wolfSSL_new(WOLFSSL_CTX* ctx);
int enc_wolfSSL_set_fd(WOLFSSL* ssl, int fd);
int enc_wolfSSL_connect(WOLFSSL* ssl);
int enc_wolfSSL_write(WOLFSSL* ssl, const void* in, int sz);
int enc_wolfSSL_get_error(WOLFSSL* ssl, int ret);
int enc_wolfSSL_read(WOLFSSL* ssl, void* out, int sz);
void enc_wolfSSL_free(WOLFSSL* ssl);
void enc_wolfSSL_CTX_free(WOLFSSL_CTX* ctx);
int enc_wolfSSL_Cleanup();

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_current_time(double* time);
sgx_status_t SGX_CDECL ocall_low_res_time(int* time);
sgx_status_t SGX_CDECL ocall_recv(size_t* retval, int sockfd, void* buf, size_t len, int flags);
sgx_status_t SGX_CDECL ocall_send(size_t* retval, int sockfd, const void* buf, size_t len, int flags);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
