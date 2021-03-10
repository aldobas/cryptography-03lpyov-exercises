/* from OpenSSL documentation */

int decrypt (int infd, int outfd) 
{ 
	unsigned char outbuf[IP_SIZE]; 
	int olen, tlen, n; 
	char inbuff[OP_SIZE]; 
	EVP_CIPHER_CTX *ctx;

	EVP_CIPHER_CTX_init (ctx); 
	EVP_DecryptInit (ctx, EVP_bf_cbc (), key, iv); 
	for (;;) 
	{ 
		bzero (& inbuff, OP_SIZE); 
		if ((n = read (infd, inbuff, OP_SIZE)) == -1) 
		{ perror ("read error"); break; } 
		else if (n == 0) break; 

		bzero (& outbuf, IP_SIZE); 
		if (EVP_DecryptUpdate (ctx, outbuf, & olen, inbuff, n) != 1) 
		{ 
			printf ("error in decrypt update\n"); return 0; 
		} 
		
		if (EVP_DecryptFinal (ctx, outbuf + olen, & tlen) != 1) 
		{ printf ("error in decrypt final\n"); return 0; 
		} 

		olen += tlen; 
		if ((n = write (outfd, outbuf, olen)) == -1) 
			perror ("write error"); 
	} 
	EVP_CIPHER_CTX_free (ctx); 
	
	return 1; 
} 
