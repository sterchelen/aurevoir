#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <stdio.h>

#include "dns_protocol.h"

int main(int argc, char *argv[]) {
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  struct sockaddr_in serv_addr = {.sin_family = AF_INET, .sin_port = htons(53)};
  inet_pton(AF_INET, "192.168.1.149", &serv_addr.sin_addr);

  struct dns_header *header = build_header();
  char *domaine_name = argv[1];
  struct dns_question *question = build_question(domaine_name);

  char *buf;
  int length = build_packet(header, question, &buf);

  sendto(sock, buf, length, 0, (struct sockaddr *)&serv_addr,
         sizeof(serv_addr));


  char answer[512];
  int recv_l = recv(sock, answer, 512,0);
  
#ifdef DEBUG
  printf("recv_l %d\n",recv_l);
#endif
  
  parse_packet(answer, length);

  free(header);
  free(question->qname);
  free(question);
  free(buf);
}
