#include <stdio.h>
#include <stdlib.h>

Device *devA = NULL;
extern void kfree(void *ptr);

void release_device(Device* dev) {
	printLine("release input device.");
}

Device* get_data_from_devA(Device* devA) {
    printLine("get data from devA.");
	return devA;
}

void excuteB() {
	Device *devB = get_data_from_devA(devA);
	/* ... */
	kfree(devB);
	release_device(devA);
}

int hypocriteCommit() {
	err = dev_request(devA);
	if(err) {
		disable_device(devA);
		return 1;
	}
}

int main() {
    devA = (Device*)malloc(sizeof(Device));
	
    excuteB();
	int result = hypocriteCommit();
	return result;
}
