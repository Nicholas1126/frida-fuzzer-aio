#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

void crash()
{
    char a[10];
    *(char *)(0) = 1;
    //strcpy(a, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    return;
}

void handleClient(char *buf)
{
    if (buf[0] % 5 == 1)
    {
        //puts("--A--");
        if (buf[1] % 6 == 1)
        {
            //puts("--AB--");
            if (buf[2] % 7 == 1)
            {
                //puts("--ABC--");
                if (buf[3] % 8 == 1)
                {
                    //puts("--ABCD--");
                    if (buf[4] % 9 == 1)
                    {
                        //printf("%02x\n", buf[4]);
                        //puts("--ABCDE--");
                        if (buf[5] % 10 == 1)
                        {
                            //puts("--ABCDEF--");
                            if (buf[6] % 11 == 1)
                            {
                                puts("--CRASH--");
                                crash();
                            }
                        }
                    }
                }
            }
        }
    }
}

int main(int argc, char **argv)
{
    char buf[100];
    FILE *input = NULL;
    input = fopen(argv[1], "r");
    if (input != 0)
    {
        fscanf(input, "%s", &buf);
        handleClient(buf);
        fclose(input);
    }

    return 0;
}
