#include <stdio.h>
#include <oxdigest.h>

int main(int argc, char* argv[]) {
	printf("%d\n", digest_offset(argv[1]));
	return 0;
}

