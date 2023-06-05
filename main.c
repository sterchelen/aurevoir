#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>

#include <curl/curl.h>
#include "mdns.h"

#define SERVICE_NAME "_elg._tcp.local"

static char addrbuffer[64];
static char entrybuffer[256];
static char namebuffer[256];

struct elgatoLight {
    bool isOn;
    int brightness;
    int temperature;
};

static mdns_string_t
ipv4ToString(char* buffer, size_t capacity, const struct sockaddr_in* addr,
                       size_t addrlen) {
	char host[NI_MAXHOST] = {0};
	char service[NI_MAXSERV] = {0};
	int ret = getnameinfo((const struct sockaddr*)addr, (socklen_t)addrlen, host, NI_MAXHOST,
	                      service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
	int len = 0;
	if (ret == 0) {
		if (addr->sin_port != 0)
			len = snprintf(buffer, capacity, "%s:%s", host, service);
		else
			len = snprintf(buffer, capacity, "%s", host);
	}
	if (len >= (int)capacity)
		len = (int)capacity - 1;
	mdns_string_t str = {
        .str = buffer,
        .length = len,
    };
	return str;
}


static size_t
putJson(void *ptr, size_t size, size_t nmemb, void *_putData) {
    const char *putData = (const char *) _putData;
    size_t realsize = ( size_t ) strlen(putData);
    memcpy(ptr, putData, realsize);
    return realsize;
}


//TODO: rework returned value
static int queryCallback(int sock, const struct sockaddr* from, size_t addrlen,
                        mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype,
                        uint16_t rclass, uint32_t ttl, const void* data, size_t size,
                        size_t name_offset, size_t name_length, size_t record_offset,
                        size_t record_length, void* user_data) {
    mdns_string_t fromaddrstr = ipv4ToString(addrbuffer, sizeof(addrbuffer),
            (const struct sockaddr_in*)from, addrlen);
	const char* entrytype = (entry == MDNS_ENTRYTYPE_ANSWER) ?
                                "answer" : "unknown";

	mdns_string_t entrystr =
	    mdns_string_extract(data, size, &name_offset, entrybuffer, sizeof(entrybuffer));

    if (rtype != MDNS_RECORDTYPE_A) {
        return 0;
    }

    struct sockaddr_in addr;
    mdns_record_parse_a(data, size, record_offset, record_length, &addr);
    mdns_string_t addrstr =
        ipv4ToString(namebuffer, sizeof(namebuffer), &addr, sizeof(addr));
#ifdef DEBUG
    printf("%.*s : %s %.*s A %.*s\n", MDNS_STRING_FORMAT(fromaddrstr), entrytype,
           MDNS_STRING_FORMAT(entrystr), MDNS_STRING_FORMAT(addrstr));
#endif

    char *url;
    int elgPort = 9123;

    if(asprintf(&url, "http://%.*s:%d/elgato/lights", MDNS_STRING_FORMAT(addrstr), elgPort) < 0) {
        return -1;
    }

    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    curl_global_init(CURL_GLOBAL_ALL);
    curl = curl_easy_init();
    if(curl) {
        struct elgatoLight *settings = (struct elgatoLight*)user_data;
        char *json;
        if (asprintf(&json,"{\"lights\":[{\"brightness\":%d,\"temperature\":%d,\"on\":%d}],"
                    "\"numberOfLights\":1}", settings->brightness, settings->temperature,
                    settings->isOn) < 0){
            return -1;
        }

        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, "Expect:");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_READFUNCTION, putJson);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(curl, CURLOPT_READDATA, json);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE, strlen(json));
        curl_easy_setopt(curl, CURLOPT_URL, url);
#ifdef DEBUG
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif

        res = curl_easy_perform(curl);
        if(res != CURLE_OK)
          fprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);

        free(url);
        free(json);
}

curl_global_cleanup();
  return 1;
}

int main(int argc, char *argv[]) {
    mdns_record_type_t record_type = MDNS_RECORDTYPE_PTR;

    int socket = mdns_socket_open_ipv4(NULL);
    size_t capacity = 2048;
    void *buffer = malloc(capacity);

    int query_id = mdns_query_send(socket, record_type, SERVICE_NAME,
            strlen (SERVICE_NAME), buffer, capacity, 0);
    if (query_id < 0)
        printf("failed to send query");

#ifdef DEBUG
    printf("reading mdns answer\n");
#endif

    struct timeval timeout = {.tv_sec = 10, .tv_usec = 0};

    int ndfs = 0;
    fd_set read_fs;
    FD_ZERO(&read_fs);
    if (socket >= ndfs)
        ndfs = socket + 1;
#ifdef DEBUG
    printf("ndfs:%d\n", ndfs);
#endif
    FD_SET(socket, &read_fs);

    int res = select(ndfs, &read_fs, 0, 0, &timeout);
    int isOn = atoi(argv[1]);
    int brightness = atoi(argv[2]);
    int temperature = atoi(argv[3]);

    struct elgatoLight *settings = malloc(sizeof(struct elgatoLight));
    settings->isOn = isOn;
    settings->brightness = brightness;
    settings->temperature = temperature;
    void *user_data = settings;

    if (res > 0) {
        if (FD_ISSET(socket, &read_fs)) {
            size_t rec = mdns_query_recv(socket, buffer, capacity, queryCallback,
                    user_data, query_id);
        }
    }

    mdns_socket_close(socket);
    free(buffer);
    free(settings);
}
