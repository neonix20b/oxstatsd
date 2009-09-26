#include <stdio.h>
#include <oxdigest.h>

int main(int argc, char* argv[]) {
	char buf[DIGEST_SIZE];
	get_digest(buf);
	printf("%s\n", buf);
	return 0;
}

