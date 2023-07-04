#include <stdio.h>

int fact(int n) {
    if (n == 0) {
        return 1;
    }
    int k = fact(n-1);
    return n * fact(n-1);
}
int main () {
    printf("", fact(3));
    printf("", fact(5));
    return 0;
}