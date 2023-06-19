#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>

#include <curl/curl.h>
#include "mdns.h"
#include "aurevoir.h"

static char addrbuffer[64];
static char entrybuffer[256];
static char namebuffer[256];

static size_t
putJson(void *ptr, size_t size, size_t nmemb, void *_putData) {
    const char *putData = (const char *) _putData;
    size_t realsize = ( size_t ) strlen(putData);
    memcpy(ptr, putData, realsize);
    return realsize;
}

static size_t
nullWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata){
    //we want this function to act as a no-op
    //this fct used as a callback must return the number of bytes
    //actually taken care of
    //(https://everything.curl.dev/libcurl/callbacks/write)
    return size * nmemb;
}

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

//TODO: rework returned value
int queryCallback(int sock, const struct sockaddr* from, size_t addrlen,
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
        aurevoir *elgatoHandle = (aurevoir*)user_data;
        char *json;
        if (asprintf(&json,"{\"lights\":[{\"brightness\":%d,\"temperature\":%d,\"on\":%d}],"
                    "\"numberOfLights\":1}", elgatoHandle->brightness, elgatoHandle->temperature,
                    elgatoHandle->isOn) < 0){
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
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, nullWriteCallback);
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

