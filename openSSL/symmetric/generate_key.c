/* bad random key generation */

int generate_key () 
{ 
	int i, j, fd;

	if ((fd = open ("/dev/random", O_RDONLY)) == -1) 
		perror ("open error"); 
	
	if ((read (fd, key, 16)) == -1) 
		perror ("read key error");
	
	if ((read (fd, iv, 8)) == -1) 
		perror ("read iv error"); 
	
	printf("128 bit key:\n"); 

	for (i = 0; i < 16; i++) 
		printf ("%d \t", key[i]); 
	printf ("\n ------ \n"); 
	
	printf("Initialization vector\n"); 
	for (i = 0; i < 8; i++) 
		printf ("%d \t", iv[i]); 
	printf ("\n ------ \n"); 
	close (fd); return 0; 
} 
