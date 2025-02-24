#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "../../in_tls.h"

#define CERT_FILE_A	"../certificate_a.pem"
#define KEY_FILE_A	"../key_a.pem"
#define CERT_FINE_B	"../certificate_b.pem"
#define KEY_FILE_B	"../key_b.pem"
#define BUFFER_SIZE	2048

void handle_req(char* req, char* resp, int num_received);

int main() {
	char servername[255];
	int servername_len = sizeof(servername);
	char request[BUFFER_SIZE];
	char response[BUFFER_SIZE];
	memset(request, 0, BUFFER_SIZE);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(443);

	int this = 0;
	int that = sizeof(int);
	int fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TLS);
	int result = setsockopt(fd, IPPROTO_TLS, TLS_VERSION_MIN, &TLS_1_2, sizeof(int));
	int version = getsockopt(fd, IPPROTO_TLS, TLS_VERSION_MIN, &this, &that);
	if (version == -1)
		fprintf(stderr, "%s\n", strerror(errno));

	printf("%d\n%d\n%d\n%d\n", version, this, that, errno);

	bind(fd, (struct sockaddr*)&addr, sizeof(addr));

	listen(fd, SOMAXCONN);

	while (1) {
		struct sockaddr_storage addr;
		socklen_t addr_len = sizeof(addr);
		int c_fd = accept(fd, (struct sockaddr*)&addr, &addr_len);

		int num_received = recv(c_fd, request, BUFFER_SIZE, 0);
		printf("Received %i bytes from client.\n", num_received);
		handle_req(request, response, num_received);
		int num_sent = send(c_fd, response, num_received+1, 0); /* +1 for EOF */
		close(c_fd);
	}
	return 0;
}

void handle_req(char* req, char* resp, int num_received) {
	memcpy(resp, req, num_received);
	resp[num_received] = '\0';
	return;
}
