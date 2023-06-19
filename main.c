#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>

#include <curl/curl.h>
#include "aurevoir.h"
#include "mdns.h"
#include "api.h"

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

    aurevoir *aurevoirHandle = aurevoirInit();
    aurevoirSetOpt(aurevoirHandle, AUREVOIROPT_LIGHT_ON, &isOn);
    aurevoirSetOpt(aurevoirHandle, AUREVOIROPT_BRIGHTNESS, &brightness);
    aurevoirSetOpt(aurevoirHandle, AUREVOIROPT_TEMPERATURE, &temperature);
    void *user_data = aurevoirHandle;

    if (res > 0) {
        if (FD_ISSET(socket, &read_fs)) {
            size_t rec = mdns_query_recv(socket, buffer, capacity,
                    &queryCallback, user_data, query_id);
        }
    }

    mdns_socket_close(socket);
    free(buffer);
    aurevoirCleanup(aurevoirHandle);

    return 0;
}
