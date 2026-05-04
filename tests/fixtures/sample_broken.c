/* Deliberately broken C file for robustness testing (Constraint A) */

#include <stdio.h>

/* Valid function before errors */
int valid_before(int x) {
    return x + 1;
}

/* Missing semicolon */
int broken_semicolon(int a) {
    int b = a + 1
    return b;
}

/* Unknown macro used as statement */
void macro_as_statement(int x) {
    UNKNOWN_MACRO(x, 42);
    int y = x + 1;
    return;
}

/* #ifdef inside function body */
void ifdef_in_body(int mode) {
    int result = 0;
#ifdef DEBUG
    printf("debug mode\n");
#endif
    result = mode + 1;
    printf("%d\n", result);
}

/* Valid function after errors */
int valid_after(int x, int y) {
    return x + y;
}

/* Unclosed brace - parser should still recover */
void unclosed(int a) {
    if (a > 0) {
        a = a + 1;
    /* missing closing brace for if */
    return;
}
