#include <stdio.h>
#include <openssl/rand.h>

#define MAX_BUF 2048

int main(int argc,char **argv) {

  int n;
  int i;
  unsigned char random_string[MAX_BUF];

  if(sscanf(argv[1],"%d",&n)==0){
    fprintf(stderr,"Problems scanning argv[1]\n");
    exit(1);
  }

  if(n>MAX_BUF){
    printf("Maximum size allowed exxeced. Set to %d\n",MAX_BUF);
    n=MAX_BUF;
  }

  /*
  (1. properly init the generator)
  2. generate sequence of psuedo-random bytes and store them in a buffer
  */

  int rc = RAND_load_file("/dev/random", 32); //good for the seed
  if(rc != 32) {
    printf("Couldnt initialize PRNG\n");
    exit(1);
  }

  RAND_bytes(random_string, n);


  printf("Sequence generated: ");
  for(i = 0; i < n; i++)
    printf("%02x", random_string[i]);
  printf("\n");

  return 0;
}
