#include <stddef.h>
#include <stdint.h>

#define MDNS_IP "224.0.0.251"
#define MDNS_PORT 5353
#define QNAME_DELIMITER ".";

#define DEBUG

/* FORMAT of DNS messages
         +---------------------+
         |        Header       | --> dns_header
         +---------------------+
         |       Question      | --> dns_question
         +---------------------+
         |        Answer       | --> dns_answer
         +---------------------+
         |      Authority      | RRs pointing toward an authority (optional)
         +---------------------+
         |      Additional     | RRs holding additional information (optional)
         +---------------------+

*/

/* HEADER format

         1  1  1  1  1  1
         0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                      ID                       |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   | <- flags (bit fields
   isn't reliable)
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                    QDCOUNT                    |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                    ANCOUNT                    |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                    NSCOUNT                    |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                    ARCOUNT                    |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

*/
struct dns_header {
  /*a 16 bit identifier assigned by the program that generates any
          kind of query.*/
  uint16_t id;
  uint16_t flags;

  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount;
};

/* Question format

         1  1  1  1  1  1
         0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                                               |
         /                     QNAME                     /
         /                                               /
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                     QTYPE                     |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
         |                     QCLASS                    |
         +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

Based on the RFC https://www.rfc-editor.org/rfc/rfc1035 
											 //(DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION)

QNAME           a domain name represented as a sequence of labels, where
                each label consists of a length octet followed by that
                number of octets.  The domain name terminates with the
                zero length octet for the null label of the root.  Note
                that this field may be an odd number of octets; no
                padding is used.

> a sequence of labels, where each label consists of a length 
> octet followed by that number of octets.

Strange, there is not mention about delimiter, the dot...

Based on the previous description, QNAME is of the following form:
raw qname = www.sterchelen.net
QNAME= 3www10sterchelen3net */

struct dns_question {
  char *qname;
  size_t qname_length;
  uint16_t qtype;
  uint16_t qclass;
};


/* Answer format


The answer, authority, and additional sections all share the same
format: a variable number of resource records, where the number of
records is specified in the corresponding count field in the header.
Each resource record has the following format:

                                    1  1  1  1  1  1
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                                               |
    /                                               /
    /                      NAME                     /
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TYPE                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     CLASS                     |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                      TTL                      |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                   RDLENGTH                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
    /                     RDATA                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

*/
struct dns_answer {
  char *name;
  uint16_t type;
  uint16_t class_code;
  uint32_t ttl;
  uint16_t rdlength;
  char *rdata;
};

struct dns_header *build_header();
struct dns_question *build_question(char *domain_name);

size_t build_packet(struct dns_header *header, struct dns_question *question,
                    char **buf);

void parse_packet(char *buf, size_t h_q_length);
