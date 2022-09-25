#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>

#include <arpa/inet.h>
#define SIZE 1024

void handleErrors(void);

int gcmfile_encrypt(unsigned char *key,
					unsigned char *iv,
					FILE *in,
					FILE *out);

void PBKDF2_HMAC_SHA3_256_string(const char *pass,
								 const unsigned char *salt,
								 int32_t iterations,
								 uint32_t iklen,
								 uint32_t ivlen,
								 char *hexResult,
								 char *key,
								 char *iv);
char *toUpper(char *str, int len);

void send_file(FILE *fp, int sockfd);

int main(int argc, char **argv)
{
	char *salt = "SodiumChloride"; // NULL;

	uint32_t iterations = 4096;

	uint32_t iklen = 32;
	uint32_t ivlen = 12;
	unsigned char key[iklen], iv[ivlen];

	int local_flag = 0;
	int ip_flag = 0;
	int c;
	char *ip = NULL;

	char *delim = ":";
	char ipv4[15];
	char port[5];

	if (argc > 4)
	{
		perror("ERROR, Encountered extra arguments. Exiting.");
		exit(1);
	}

	char *inFile = argv[1];

	while ((c = getopt(argc, argv, "ld:")) != -1)
		switch (c)
		{
		case 'l':
			local_flag = 1;
			break;
		case 'd':
			ip_flag = 1;
			ip = optarg;
			char *ipv4_t = strtok(ip, delim);
			strcpy(ipv4, ipv4_t);
			char *port_t = strtok(NULL, ":");
			strcpy(port, port_t);
			// printf("Ipv4 : %s\n",ipv4);
			// printf("port : %s\n",port);
			break;
		}

	// printf("%d, \n%s \n%s \n", local_flag, ip, inFile);

	if (access(inFile, F_OK) != 0)
	{
		perror("ERROR, File to encrypt is missing.");
		exit(1);
	}

	FILE *toenc_file, *enc_file;
	toenc_file = fopen(inFile, "r");

	char *ext = ".ufsec";
	char *encfilename = strcat(inFile, ext);

	// check if encrypted file exists
	if (access(encfilename, F_OK) == 0)
	{
		perror("Encrypted file exists.\n");
		return 33;
	}

	// User Input Password
	char pass[255];
	printf("\nPassword: ");
	scanf("%s", pass);

	// printf("Computing PBKDF2(HMAC-SHA3-256, '%s', '%s', %d, %d) ...\n", pass, salt, iterations, iklen);

	char hexResult[2 * iklen + 1];
	memset(hexResult, 0, sizeof(hexResult));

	char *finResult = NULL;

	PBKDF2_HMAC_SHA3_256_string(pass, salt, iterations, iklen, ivlen, hexResult, key, iv);

	finResult = toUpper(hexResult, strlen(hexResult));

	printf("Hex password is %s\n", finResult);

	if (local_flag)
	{
		enc_file = fopen(encfilename, "w");

		gcmfile_encrypt(key, iv, toenc_file, enc_file);

		fclose(toenc_file);
		fclose(enc_file);
	}

	if (ip_flag)
	{

		int e;

		int sockfd;
		struct sockaddr_in server_addr;
		FILE *fp;
		// char *filename = encfilename;

		sockfd = socket(AF_INET, SOCK_STREAM, 0);
		if (sockfd < 0)
		{
			perror("Socket error.");
			exit(1);
		}
		// printf("Server socket created.\n");

		server_addr.sin_family = AF_INET;
		server_addr.sin_port = atoi(port);
		server_addr.sin_addr.s_addr = inet_addr(ipv4);

		e = connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		if (e == -1)
		{
			perror("Socket error.");
			exit(1);
		}
		// printf("Connection established. \n");

		enc_file = fopen(encfilename, "w");

		gcmfile_encrypt(key, iv, toenc_file, enc_file);

		fclose(toenc_file);
		fclose(enc_file);

		fp = fopen(encfilename, "r");
		if (fp == NULL)
		{
			perror("Error in reading file.");
			exit(1);
		}

		printf("Transmitting to %s:%s\n", ipv4, port);
		send_file(fp, sockfd);
		printf("File sent successfully.\n");

		fclose(fp);
		close(sockfd);
	}
}

void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}

void send_file(FILE *fp, int sockfd)
{
	int n;
	char data[SIZE] = {0};
	while (!feof(fp))
	{
		if ((n = fread(&data, 1, sizeof(data), fp)) > 0)
			send(sockfd, data, n, 0);
		else
			break;
	}
}

void PBKDF2_HMAC_SHA3_256_string(const char *pass,
								 const unsigned char *salt,
								 int32_t iterations,
								 uint32_t iklen,
								 uint32_t ivlen,
								 char *hexResult,
								 char *key,
								 char *iv)
{
	unsigned int i;

	unsigned char tmpkey[iklen];
	PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha3_256(), iklen, tmpkey);

	/* generate iv and store key generated*/
	memcpy(key, tmpkey, iklen);

	RAND_bytes(iv, ivlen);

	// BIO_dump_fp (stdout, (const char *)iv, ivlen); //print IV

	char hexResult_h[iklen];
	memcpy(hexResult_h, tmpkey, iklen);
	for (i = 0; i < sizeof(hexResult_h); i++)
		sprintf(hexResult + (i * 2), "%02x", 255 & hexResult_h[i]);
}

char *toUpper(char *str, int len)
{
	unsigned int i;
	char *out = (char *)malloc(len);
	for (i = 0; i < len; i++)
		*(out + i) = toupper(*(str + i));
	return out;
}

int gcmfile_encrypt(unsigned char *key,
					unsigned char *iv,
					FILE *in, FILE *out)
{
	char inbuf[SIZE];
	char outbuf[SIZE + EVP_MAX_BLOCK_LENGTH];
	int inlen = 0, flen = 0, outlen = 0;
	int total_len = 0;

	uint32_t ivlen = 12;

	fwrite(iv, 1, ivlen, out);
	// BIO_dump_fp (stdout, (const char *)iv, ivlen);

	// begin encrypting

	EVP_CIPHER_CTX *ctx;

	/* Create and initialise the context */
	if (!(ctx = EVP_CIPHER_CTX_new()))
		handleErrors();

	/* Initialise the encryption operation. */
	if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
		handleErrors();

	if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
		handleErrors();

	while ((inlen = fread(inbuf, 1, SIZE, in)) > 0)
	{

		if (!EVP_EncryptUpdate(ctx, (unsigned char *)outbuf, &outlen, (unsigned char *)inbuf, inlen)) /* Update cipher text */
		{
			perror("\n ERROR,ENCRYPT_UPDATE:");
			return 1;
		}

		BIO_dump_fp(stdout, (const char *)outbuf, outlen);
		if (fwrite(outbuf, 1, outlen, out) != outlen)
		{
			perror("\n ERROR,Cant write encrypted bytes to outfile:");
			return 1;
		}
		total_len += outlen;
	}

	if (!EVP_EncryptFinal_ex(ctx, (unsigned char *)outbuf, &flen)) /* updates the remaining bytes */
	{
		perror("\n ERROR,ENCRYPT_FINAL:");
		return 1;
	}

	total_len += flen;
	BIO_dump_fp(stdout, (const char *)outbuf, flen);

	printf("%d bytes encrypted.\n", total_len);
	if (fwrite(outbuf, 1, flen, out) != flen)
	{
		perror("\n ERROR,Writing final bytes of data:");
		return 1;
	}

	/*Free cipher/evp ctx*/
	EVP_CIPHER_CTX_free(ctx);

	return 0;
}
