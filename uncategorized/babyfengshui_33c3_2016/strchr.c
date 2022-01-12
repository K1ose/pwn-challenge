#include <stdio.h>
#include <string.h>

int main(){
    const char str[] = "2010http://www.jk404.cnABCabccderewlkrj!we";
    int c = 33;
    char *ret;
    ret = strchr(str, c);
    printf("ret => %s", ret);
}