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
#define default_port 8080

void handleErrors(void);

int gcmfile_decrypt(unsigned char *key,
                    unsigned char *iv,
                    FILE *in,
                    FILE *out);

void PBKDF2_HMAC_SHA3_256_string(const char *pass,
                                 const unsigned char *salt,
                                 int32_t iterations,
                                 uint32_t iklen,
                                 uint32_t ivlen,
                                 char *hexResult,
                                 char *key, char *iv);

void write_file(int sockfd, char *fname);

char *toUpper(char *str, int len);

void send_file(FILE *fp, int sockfd);

int main(int argc, char **argv)
{
  /*
   * Set up the key and iv. Do I need to say to not hard code these in a
   * real application? :-)
   */

  char *salt = "SodiumChloride"; // NULL;

  int local_flag = 0;
  int ip_flag = 0;
  int c;
  // char* ip=NULL;
  int port = default_port;

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
      port = atoi(optarg);
      break;
    }

  // printf("%d, \n%d \n%s \n", local_flag, port, inFile);

  uint32_t passlen = 0;
  uint32_t iterations = 4096;

  uint32_t iklen = 32;
  uint32_t ivlen = 12;
  unsigned char key[iklen], iv[ivlen];

  int in, out, fd, dec;

  if (ip_flag)
  {
    int e;

    int sockfd, new_sock;
    struct sockaddr_in server_addr, new_addr;
    socklen_t addr_size;
    char buffer[SIZE];

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
      perror("Socket error.");
      exit(1);
    }
    printf("Server socket created.\n");
    // printf("%d", port);
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = port;
    server_addr.sin_addr.s_addr = INADDR_ANY; // inet_addr(ip);

    e = bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (e < 0)
    {
      perror("Bind error.");
      exit(1);
    }
    // printf("binding\n");

    if (listen(sockfd, 10) == 0)
    {
      printf("Waiting for connections.\n");
    }
    else
    {
      perror("Couldn't wait.");
      exit(1);
    }

    addr_size = sizeof(new_addr);
    new_sock = accept(sockfd, (struct sockaddr *)&new_addr, &addr_size);
    printf("Inbound file.\n");
    write_file(new_sock, inFile);
    printf("Data written in the file %s successfully.\n", inFile);
  }

  FILE *enc_file_fp, *dec_file_fp;

  char *ext = ".ufsec";

  if (!(strlen(inFile) > 4 && !strcmp(inFile + strlen(inFile) - strlen(ext), ext)))
  {
    perror("ERROR, File not acceptable.\n");
    exit(1);
  }

  enc_file_fp = fopen(inFile, "r");

  int len1 = strlen(inFile);
  char *outFile = strndup(inFile, len1 >= strlen(ext) ? len1 - strlen(ext) : 0);

  if (access(outFile, F_OK) == 0)
  {
    perror("ERROR, Decrypted file exists.\n");
    return 33;
  }

  // User Input Password
  char pass[255];
  printf("Password: ");
  scanf("%s", pass);

  // Hardcoded password
  // char* pass = "Hello";

  // printf("Computing PBKDF2(HMAC-SHA3-256, '%s', '%s', %d, %d) ...\n", pass, salt, iterations, iklen);

  char hexResult[2 * iklen + 1];
  memset(hexResult, 0, sizeof(hexResult));

  char *finResult = NULL;

  PBKDF2_HMAC_SHA3_256_string(pass, salt, iterations, iklen, ivlen, hexResult, key, iv);

  finResult = toUpper(hexResult, strlen(hexResult));

  printf("Hex password is %s\n", finResult);

  dec_file_fp = fopen(outFile, "w");

  gcmfile_decrypt(key, iv, enc_file_fp, dec_file_fp);
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int fsize(FILE *fp)
{
  int prev = ftell(fp);
  fseek(fp, 0L, SEEK_END);
  int sz = ftell(fp);
  fseek(fp, prev, SEEK_SET); // go back to where we were
  return sz;
}

char *toUpper(char *str, int len)
{
  unsigned int i;
  char *out = (char *)malloc(len);
  for (i = 0; i < len; i++)
    *(out + i) = toupper(*(str + i));
  return out;
}

int gcmfile_decrypt(unsigned char *key,
                    unsigned char *iv,
                    FILE *in,
                    FILE *out)
{
  char inbuf[SIZE];
  char outbuf[SIZE + EVP_MAX_BLOCK_LENGTH];
  int inlen = 0, flen = 0, outlen = 0;
  int total_len = 0;

  // char iv_temp[strlen(iv)];
  // fread(iv_temp,1,strlen(iv),in);

  uint32_t ivlen = 12;

  char iv_temp[ivlen];
  fread(iv_temp, 1, ivlen, in);

  // printf("IV size %ld strlen %ld\n", sizeof(iv_temp), strlen(iv_temp));
  // BIO_dump_fp (stdout, (const char *)iv_temp, ivlen);

  // begin decrypting

  EVP_CIPHER_CTX *ctx;

  /* Create and initialise the context */
  if (!(ctx = EVP_CIPHER_CTX_new()))
    handleErrors();

  /* Initialise the decryption operation. */
  if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    handleErrors();

  /* Initialise key and IV */
  if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv_temp))
    handleErrors();

  while ((inlen = fread(inbuf, 1, SIZE, in)) > 0)
  {
    // printf("%s",inbuf);
    if (!EVP_DecryptUpdate(ctx, (unsigned char *)outbuf, &outlen, (unsigned char *)inbuf, inlen)) /* decrypt cipher text */
    {
      perror("\n ERROR,DECRYPT_UPDATE:");
      return 1;
    }

    BIO_dump_fp(stdout, (const char *)outbuf, outlen);
    if (fwrite(outbuf, 1, outlen, out) != outlen)
    {
      perror("\n ERROR,Cant write decrypted bytes to outfile:");
      return 1;
    }
    total_len += outlen;
  }
  printf("\n");
  printf("%d bytes decrypted.\n", total_len);

  /*Free cipher/evp ctx*/
  EVP_CIPHER_CTX_free(ctx);

  return 0;
}

void PBKDF2_HMAC_SHA3_256_string(const char *pass,
                                 const unsigned char *salt,
                                 int32_t iterations,
                                 uint32_t iklen,
                                 uint32_t ivlen,
                                 char *hexResult,
                                 char *key, char *iv)
{
  unsigned int i;

  unsigned char tmpkey[iklen];
  PKCS5_PBKDF2_HMAC(pass, strlen(pass), salt, strlen(salt), iterations, EVP_sha3_256(), iklen, tmpkey);

  /* generate iv and store key generated*/
  memcpy(key, tmpkey, iklen);

  RAND_bytes(iv, ivlen);
  // BIO_dump_fp (stdout, (const char *)iv, ivlen);

  char hexResult_h[iklen];
  memcpy(hexResult_h, tmpkey, iklen);
  for (i = 0; i < sizeof(hexResult_h); i++)
    sprintf(hexResult + (i * 2), "%02x", 255 & hexResult_h[i]);
}

void write_file(int sockfd, char *fname)
{
  int n;
  FILE *fp;
  char *filename = fname;
  char buffer[SIZE];
  int total_len = 0;
  fp = fopen(filename, "w");
  while (1)
  {
    n = recv(sockfd, buffer, sizeof(buffer), 0);
    if (n <= 0)
    {
      break;
      return;
    }

    BIO_dump_fp(stdout, (const char *)buffer, n);
    fwrite(&buffer, 1, n, fp);

    total_len += n;

    // fprintf(fp, "%s", buffer);
    // bzero(buffer, SIZE);
  }
  BIO_dump_fp(stdout, (const char *)buffer, n);
  printf("%d bytes downloaded.\n", total_len);
  fclose(fp);
  return;
}