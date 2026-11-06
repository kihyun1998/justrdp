/* Drives the key derivation, MAC and key update of libfreerdp/core/security.c for one client and
 * one server, and prints what they produce. security_body.c is that file with its #include lines
 * removed (run.sh). */
#include "shim.h"
#define TAG "core"
#define FREERDP_TAG(x) x
#include "security_body.c"

static EVP_MD_CTX* total;

static void hex(const char* label, const BYTE* d, size_t n)
{
	printf(" %s=", label);
	for (size_t i = 0; i < n; i++)
		printf("%02x", d[i]);
}

static int interesting(UINT32 i)
{
	return i < 3 || (i >= 4095 && i <= 4098) || i == 8192;
}

/* Packet i: 1 + i % 31 bytes, byte j is (i + j) & 0xff; every third MAC is salted. */
static void run(const char* dir, rdpRdp* sender, rdpRdp* receiver)
{
	EVP_DigestInit_ex(total, EVP_md5(), NULL);
	for (UINT32 i = 0; i < 8200; i++)
	{
		BYTE plain[32], data[32], sig[8], cmac[8];
		const UINT32 len = 1 + i % 31;
		const BOOL salted = i % 3 == 0;
		for (UINT32 j = 0; j < len; j++)
			plain[j] = data[j] = (BYTE)(i + j);
		if (salted)
			security_salted_mac_signature(sender, data, len, TRUE, sig, 8);
		else
			security_mac_signature(sender, data, len, sig, 8);
		security_encrypt(data, len, sender);
		EVP_DigestUpdate(total, sig, 8);
		EVP_DigestUpdate(total, data, len);
		if (interesting(i))
		{
			printf("%s i=%u", dir, i);
			hex("sig", sig, 8);
			hex("ct", data, len);
			printf("\n");
		}
		security_decrypt(data, len, receiver);
		if (salted)
			security_salted_mac_signature(receiver, data, len, FALSE, cmac, 8);
		else
			security_mac_signature(receiver, data, len, cmac, 8);
		if (memcmp(data, plain, len) != 0 || memcmp(cmac, sig, 8) != 0)
		{
			fprintf(stderr, "receiver disagrees at %s %u\n", dir, i);
			exit(1);
		}
	}
	BYTE digest[16];
	EVP_DigestFinal_ex(total, digest, NULL);
	printf("%s", dir);
	hex("md5_all", digest, 16);
	printf("\n");
}

int main(void)
{
	static const UINT32 methods[] = { ENCRYPTION_METHOD_40BIT, ENCRYPTION_METHOD_56BIT, ENCRYPTION_METHOD_128BIT };
	total = EVP_MD_CTX_new();
	for (size_t m = 0; m < 3; m++)
	{
		rdpSettings cs = { 0 };
		rdpSettings ss = { 0 };
		rdpRdp client = { 0 };
		rdpRdp server = { 0 };
		for (int i = 0; i < 32; i++)
		{
			cs.ClientRandom[i] = ss.ClientRandom[i] = (BYTE)(0x10 + i);
			cs.ServerRandom[i] = ss.ServerRandom[i] = (BYTE)(0xE0 ^ (i * 7));
		}
		cs.EncryptionMethods = ss.EncryptionMethods = methods[m];
		ss.ServerMode = TRUE;
		client.settings = &cs;
		server.settings = &ss;
		if (!security_establish_keys(&client) || !security_establish_keys(&server))
			return 1;
		rdp_reset_rc4_encrypt_keys(&client);
		rdp_reset_rc4_decrypt_keys(&client);
		rdp_reset_rc4_encrypt_keys(&server);
		rdp_reset_rc4_decrypt_keys(&server);
		printf("method=%u", methods[m]);
		hex("mac", client.sign_key, client.rc4_key_len);
		hex("client_encrypt", client.encrypt_key, client.rc4_key_len);
		hex("client_decrypt", client.decrypt_key, client.rc4_key_len);
		printf("\n");
		run("c2s", &client, &server);
		run("s2c", &server, &client);
	}
	return 0;
}
