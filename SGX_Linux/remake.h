make clean  WOLFSSL_ROOT=~/wolfssl
make SGX_MODE=SIM SGX_PRERELEASE=0 SGX_WOLFSSL_LIB=~/wolfssl/IDE/LINUX-SGX/ WOLFSSL_ROOT=~/wolfssl SGX_DEBUG=1 HAVE_WOLFSSL_TEST=1

./App -s