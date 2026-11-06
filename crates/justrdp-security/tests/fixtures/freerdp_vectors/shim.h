/* What libfreerdp/core/security.c needs from winpr and rdpRdp, over OpenSSL. */
#include <openssl/evp.h>
#include <openssl/rc4.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint8_t BYTE;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef int BOOL;
#define TRUE 1
#define FALSE 0
#define nullptr NULL
#define WINPR_C_ARRAY_INIT { 0 }
#define WINPR_ASSERT(x) ((void)0)
#define WINPR_ATTR_UNUSED
#define WINPR_CXX_COMPAT_CAST(t, x) ((t)(x))
#define WINPR_SHA1_DIGEST_LENGTH 20
#define WINPR_MD5_DIGEST_LENGTH 16
#define WLog_ERR(...) ((void)0)
#define WLog_WARN(...) ((void)0)
#define WLog_DBG(...) ((void)0)
#define WLog_Print(...) ((void)0)
#define WLOG_ERROR 0
#define WINPR_ENCRYPT 0
#define WINPR_DECRYPT 1

typedef EVP_MD_CTX WINPR_DIGEST_CTX;
typedef int WINPR_HMAC_CTX;
typedef int WINPR_CIPHER_CTX;
typedef RC4_KEY WINPR_RC4_CTX;
enum { WINPR_MD_MD5, WINPR_MD_SHA1 };

static WINPR_DIGEST_CTX* winpr_Digest_New(void) { return EVP_MD_CTX_new(); }
static void winpr_Digest_Free(WINPR_DIGEST_CTX* c) { EVP_MD_CTX_free(c); }
static BOOL winpr_Digest_Init(WINPR_DIGEST_CTX* c, int md)
{
	return EVP_DigestInit_ex(c, md == WINPR_MD_MD5 ? EVP_md5() : EVP_sha1(), NULL);
}
#define winpr_Digest_Init_Allow_FIPS winpr_Digest_Init
static BOOL winpr_Digest_Update(WINPR_DIGEST_CTX* c, const BYTE* d, size_t n)
{
	return EVP_DigestUpdate(c, d, n);
}
static BOOL winpr_Digest_Final(WINPR_DIGEST_CTX* c, BYTE* o, size_t n)
{
	(void)n;
	return EVP_DigestFinal_ex(c, o, NULL);
}

/* The FIPS paths are never taken here. */
static WINPR_HMAC_CTX* winpr_HMAC_New(void) { abort(); }
static BOOL winpr_HMAC_Init(WINPR_HMAC_CTX* c, int m, const BYTE* k, size_t n) { abort(); }
static BOOL winpr_HMAC_Update(WINPR_HMAC_CTX* c, const BYTE* d, size_t n) { abort(); }
static BOOL winpr_HMAC_Final(WINPR_HMAC_CTX* c, BYTE* o, size_t n) { abort(); }
static void winpr_HMAC_Free(WINPR_HMAC_CTX* c) { abort(); }
static BOOL winpr_Cipher_Update(WINPR_CIPHER_CTX* c, const void* i, size_t n, void* o, size_t* w) { abort(); }
#define WINPR_MD_SHA1_HMAC WINPR_MD_SHA1

static WINPR_RC4_CTX* winpr_RC4_New(const BYTE* k, size_t n)
{
	WINPR_RC4_CTX* c = malloc(sizeof *c);
	RC4_set_key(c, (int)n, k);
	return c;
}
static BOOL winpr_RC4_Update(WINPR_RC4_CTX* c, size_t n, const BYTE* i, BYTE* o)
{
	RC4(c, n, i, o);
	return TRUE;
}
static void winpr_RC4_Free(WINPR_RC4_CTX* c) { free(c); }

#define ENCRYPTION_METHOD_NONE 0
#define ENCRYPTION_METHOD_40BIT 1
#define ENCRYPTION_METHOD_128BIT 2
#define ENCRYPTION_METHOD_56BIT 8
#define ENCRYPTION_METHOD_FIPS 16

typedef struct
{
	UINT32 EncryptionMethods;
	BOOL ServerMode;
	BYTE ClientRandom[32];
	BYTE ServerRandom[32];
} rdpSettings;
enum { FreeRDP_ServerRandom, FreeRDP_ClientRandom, FreeRDP_ClientRandomLength, FreeRDP_ServerRandomLength };
static const BYTE* freerdp_settings_get_pointer(const rdpSettings* s, int k)
{
	return k == FreeRDP_ServerRandom ? s->ServerRandom : s->ClientRandom;
}
static UINT32 freerdp_settings_get_uint32(const rdpSettings* s, int k) { (void)s; (void)k; return 32; }

typedef struct
{
	rdpSettings* settings;
	BYTE sign_key[16], encrypt_key[16], decrypt_key[16], encrypt_update_key[16], decrypt_update_key[16];
	size_t rc4_key_len;
	WINPR_RC4_CTX* rc4_encrypt_key;
	WINPR_RC4_CTX* rc4_decrypt_key;
	UINT32 encrypt_use_count, decrypt_use_count, encrypt_checksum_use_count, decrypt_checksum_use_count;
	BYTE fips_sign_key[20], fips_encrypt_key[24], fips_decrypt_key[24];
	WINPR_CIPHER_CTX* fips_encrypt;
	WINPR_CIPHER_CTX* fips_decrypt;
	int critical;
} rdpRdp;
#define EnterCriticalSection(x) ((void)0)
#define LeaveCriticalSection(x) ((void)0)

static BOOL rdp_reset_rc4_encrypt_keys(rdpRdp* rdp)
{
	if (rdp->rc4_encrypt_key)
		winpr_RC4_Free(rdp->rc4_encrypt_key);
	rdp->rc4_encrypt_key = winpr_RC4_New(rdp->encrypt_key, rdp->rc4_key_len);
	rdp->encrypt_use_count = 0;
	return TRUE;
}
static BOOL rdp_reset_rc4_decrypt_keys(rdpRdp* rdp)
{
	if (rdp->rc4_decrypt_key)
		winpr_RC4_Free(rdp->rc4_decrypt_key);
	rdp->rc4_decrypt_key = winpr_RC4_New(rdp->decrypt_key, rdp->rc4_key_len);
	rdp->decrypt_use_count = 0;
	return TRUE;
}
