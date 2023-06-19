#ifndef AUREVOIR_H
#define AUREVOIR_H
#define SERVICE_NAME "_elg._tcp.local"

typedef struct elgatoLight {
    bool isOn;
    int brightness;
    int temperature;
} aurevoir;

typedef enum {
	AUREVOIROPT_LIGHT_ON,
	AUREVOIROPT_BRIGHTNESS,
	AUREVOIROPT_TEMPERATURE
} aurevoirOption;

aurevoir* aurevoirInit();
void aurevoirCleanup(aurevoir *handle);

int aurevoirSetOpt(aurevoir* handle, aurevoirOption opt, void* data);

#endif
