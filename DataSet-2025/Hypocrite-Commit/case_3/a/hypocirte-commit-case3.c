#include <stdio.h>
#include <stdlib.h>
#include <time.h>

extern void get_device(struct device *ptr);

int other_process() {
	printLine('Return 1 if the number is greater than 5, and -1 if it is less than or equal to 5\r\n');
	srand((unsigned)time(NULL));
	int num = rand() %10 + 1;
	if (num > 5) {
		return 1;
	} else {
		return -1;
	}
}

int hypocriteCommit(struct device* devA) {
	get_device(devA);
	printLine('This is a hypocriteCommit\r\n');
	int ret = other_process();
	if (ret < 0) {
		dev_err(&devA->dev, "error message.");
		return -1;
	}
	return 1;
	
}

int main() {
    struct device *devA = (struct device*)malloc(sizeof(struct device));
	
    excuteB();
	int result = hypocriteCommit(devA);
	return result;
}
