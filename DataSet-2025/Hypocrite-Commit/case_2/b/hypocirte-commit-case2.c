#include <stdio.h>
#include <stdlib.h>

extern void kfree(void *ptr);

int allocate_and_process_memory(char *pointerC) {
    char *pointerA = NULL;
    char *pointerB = NULL;
    
    pointerA = pointerC = (char *)malloc(sizeof(char) * 5);
    for (int i = 0; i < 5; i++) {
        pointerA[i] = i + 'a';
    }
	
    pointerB = (char *)malloc(sizeof(char) * 4);
    if (!pointerB) {
        kfree(pointerA);
        return -1;
    }
    
    for (int i = 0; i < 4; i++) {
        pointerB[i] = i + '0';
    }
    
	for (int i = 0; i < 4; i++) {
        printf("%c ", pointerB[i]);
    }
	
    kfree(pointerB);
    
    return 0;
}

int main() {
    char *data = NULL;
 
    int result = allocate_and_process_memory(data);
    if (result != 0) {
        printf("error\n");
    }
    
    strcpy(data, "hello");
	
    return 0;
}
