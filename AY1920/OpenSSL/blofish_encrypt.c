/* from OpenSSL documentation */

int encrypt (int infd, int outfd) 
{ 
	unsigned char outbuf[OP_SIZE]; 
	int olen, tlen, n; 
	char inbuff[IP_SIZE]; 
	EVP_CIPHER_CTX *ctx; 

	EVP_CIPHER_CTX_init (ctx); 
	EVP_EncryptInit (ctx, EVP_bf_cbc (), key, iv); 
	for (;;) 
	{ 
		bzero (& inbuff, IP_SIZE); 
		if ((n = read (infd, inbuff, IP_SIZE)) == -1) 
		{ 
			perror ("read error"); break; 
		} 
			else if (n == 0) break;

		if (EVP_EncryptUpdate (& ctx, outbuf, & olen, inbuff, n) != 1) 
		{ printf ("error in encrypt update\n"); return 0; 
		} 

		if (EVP_EncryptFinal (& ctx, outbuf + olen, & tlen) != 1) 
		{ 
		printf ("error in encrypt final\n"); return 0; 
		} 		
		olen += tlen; 
		if ((n = write (outfd, outbuf, olen)) == -1) 
			perror ("write error"); 
	} 
	EVP_CIPHER_CTX_free (ctx); return 1; 
}

