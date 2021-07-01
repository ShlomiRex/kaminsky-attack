#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
int main() {
	int subdomainsize = 6;
	int querysize = subdomainsize + strlen(".example.com");
	
	srand(time(NULL)); //seed random
	
	char query[querysize]; //this is the whole domain
	
	for(int i = 0; i < subdomainsize; i++) {
		query[i] = 'a' + (rand() % 26);
	}

	strcat(query, ".example.com");
	printf("query = %s\n", query);

	//execute the dig command
	char command[50];
	memset(command, 0, 50);
	strcat(command, "dig ");
	strcat(command, query);
	system(command);
}
