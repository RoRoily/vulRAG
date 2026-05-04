#include <stdio.h>
#include <stdlib.h>

#define MAX_SIZE 100
#define SAFE_FREE(p) do { if(p) { free(p); (p) = NULL; } } while(0)

typedef struct {
    int x;
    int y;
    int *data;
} Point;

/* Simple linear function */
int add(int a, int b) {
    return a + b;
}

/* If/else branching */
int classify(int value) {
    int result;
    if (value > 0) {
        result = 1;
    } else if (value < 0) {
        result = -1;
    } else {
        result = 0;
    }
    return result;
}

/* Multiple loop types */
void loop_examples(int *arr, int size) {
    int i;
    int sum = 0;

    for (i = 0; i < size; i++) {
        sum += arr[i];
    }

    int j = 0;
    while (j < size) {
        if (arr[j] == 0) {
            break;
        }
        j++;
    }

    int k = 0;
    do {
        k++;
    } while (k < 10);

    printf("sum=%d, j=%d, k=%d\n", sum, j, k);
}

/* Switch with fall-through */
const char* status_string(int code) {
    const char *msg;
    switch (code) {
        case 0:
            msg = "OK";
            break;
        case 1:
            msg = "WARNING";
            break;
        case 2:
        case 3:
            msg = "ERROR";
            break;
        default:
            msg = "UNKNOWN";
            break;
    }
    return msg;
}

/* Goto for error handling */
int resource_handler(int flag) {
    int *buffer = NULL;
    int result = -1;

    buffer = (int *)malloc(MAX_SIZE * sizeof(int));
    if (buffer == NULL) {
        goto cleanup;
    }

    if (flag < 0) {
        goto cleanup;
    }

    buffer[0] = flag;
    result = buffer[0] + 1;

cleanup:
    if (buffer != NULL) {
        free(buffer);
    }
    return result;
}

/* Pointer, struct, and array assignments for DEF/USE testing */
void pointer_struct_test(Point *pt, int *arr, int n) {
    pt->x = 10;
    pt->y = pt->x + 5;
    *arr = 42;
    arr[0] = pt->x;
    arr[n] = pt->y;
    pt->data[0] = arr[n];

    Point local;
    local.x = 1;
    local.y = local.x + 2;
}

/* Macro calls treated as regular call_expression */
void macro_usage(int *buf, int size) {
    SAFE_FREE(buf);
    MEMSET(buf, 0, size);
}

/* Long function for semantic block chunking (>30 lines) */
void complex_processing(int *data, int len, int mode) {
    int i;
    int temp;
    int total = 0;
    int max_val = data[0];
    int min_val = data[0];

    for (i = 0; i < len; i++) {
        if (data[i] > max_val) {
            max_val = data[i];
        }
        if (data[i] < min_val) {
            min_val = data[i];
        }
        total += data[i];
    }

    if (mode == 1) {
        for (i = 0; i < len; i++) {
            data[i] = data[i] - min_val;
        }
    } else if (mode == 2) {
        for (i = 0; i < len; i++) {
            if (max_val != 0) {
                data[i] = (data[i] * 100) / max_val;
            }
        }
    } else {
        for (i = 0; i < len; i++) {
            data[i] = 0;
        }
    }

    switch (mode) {
        case 1:
            printf("normalized by min\n");
            break;
        case 2:
            printf("normalized by max\n");
            break;
        default:
            printf("zeroed\n");
            break;
    }

    for (i = 0; i < len; i++) {
        temp = data[i];
        data[i] = temp + total;
    }
}
