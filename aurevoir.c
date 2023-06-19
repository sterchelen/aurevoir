#include <stdlib.h>

#include "aurevoir.h"

aurevoir* aurevoirInit() {
    aurevoir *elgatoHandle = malloc(sizeof(aurevoir));
    return elgatoHandle;
}

void aurevoirCleanup(aurevoir *handle) {
    free(handle);
}

int aurevoirSetOpt(aurevoir* handle, aurevoirOption opt, void* data){
    switch (opt) {
        case AUREVOIROPT_LIGHT_ON:
            handle->isOn = *(int*)data;
            break;
        case AUREVOIROPT_TEMPERATURE:
            handle->temperature = *(int*)data;
            break;
        case AUREVOIROPT_BRIGHTNESS:
            handle->brightness = *(int*)data;
            break;
        default:
    }
}
