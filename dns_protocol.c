#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <stdbool.h>

#include "dns_protocol.h"

struct dns_header *build_header() {
  struct dns_header *header;
  header = malloc(sizeof(struct dns_header));
  memset(header, 0, sizeof(struct dns_header));
  srandom(time(NULL));
  header->id = random();
  /* recursive asked */
  /* first version was using bit fields for header's flags...
   * C99 standard 6.7.2.1/10 the order of allocation of bit fields 
   * in C is implementation-defined so portability over network is hard
   */
  header->flags |= htons(0x0100);
  header->qdcount = htons(1);

  return header;
}

struct dns_question *build_question(char *domain_name) {
  struct dns_question *question;
  question = malloc(sizeof(struct dns_question));
  question->qtype = htons(1);
  question->qclass = htons(1);
  /* +2 b/c we have the first bit containing the length of the first label
   * and the terminated string code. */
  question->qname_length = strlen(domain_name) + 2;

  char *domain_dup = strdup(domain_name);
  const char *delimiter = QNAME_DELIMITER;

  question->qname = malloc(sizeof(domain_name) + 2);

  char *qname_p = question->qname;
  char *qname_label = strtok(domain_dup, delimiter);
  int label_len;

  while (qname_label != NULL) {
    label_len = strlen(qname_label);
    *qname_p = label_len;
    qname_p++;
    strncpy(qname_p, qname_label, label_len);
    qname_p += label_len;
    qname_label = strtok(NULL, delimiter);
  }

  free(domain_dup);
  return question;
}

size_t build_packet(struct dns_header *header, struct dns_question *question,
                    char **buf) {
  int length = sizeof(struct dns_header) + question->qname_length +
               sizeof(question->qtype) + sizeof(question->qclass);
  int offset = 0;

  *buf = malloc(sizeof(struct dns_header) + sizeof(struct dns_question));
  memcpy(*buf, header, sizeof(struct dns_header));
  offset += sizeof(struct dns_header);

  memcpy(*buf + offset, question->qname, question->qname_length);
  offset += question->qname_length;
  memcpy(*buf + offset, &question->qtype, sizeof(question->qtype));
  offset += sizeof(question->qtype);
  memcpy(*buf + offset, &question->qclass, sizeof(question->qclass));

  return length;
}

void parse_packet(char *buf, size_t h_q_length) {
	struct dns_header *header;
	header = malloc(sizeof(struct dns_header));
	memcpy(header, buf, sizeof(struct dns_header));

	int answer_count = ntohs(header->ancount);

#ifdef DEBUG
	printf("received %d answer count\n", answer_count);
#endif

	char *answer_section = buf + h_q_length;

	bool is_compressed = (*answer_section & (1<<7)) && (*answer_section & (1<<6));

#ifdef DEBUG
	printf("label length: %d\n", *answer_section );
	printf("is compressed: %d\n", is_compressed);
#endif

	if(is_compressed) {
		// remove two first bits that are used to know if we are in a compressed
		// situation
		uint16_t name_offset = (ntohs(*(uint16_t *)answer_section) & 0x3fff);
		char *name_ptr = buf + name_offset;
		int name_lgth = strlen(name_ptr);
		char *name_cpy = calloc(name_lgth, sizeof(char));
		int i = 0;

		while(*name_ptr){
			size_t label_len = *name_ptr;
			memcpy(name_cpy + i, name_ptr + 1, label_len);
			
			i+= label_len;
			name_ptr += label_len + 1;
			if (*name_ptr) {
				name_cpy[i++] = '.';
			}
			printf("name_cpy %s, i %d, name_ptr %d label_len %ld\n",name_cpy, i,*name_ptr,label_len);
		}
		printf("complete string: %s\n",name_cpy);
	}
}
