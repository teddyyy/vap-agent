#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>

#include "agent.h"

void do_debug(char *msg, ...)
{
    va_list args;

    if (debug) {
        va_start(args, msg);
        vfprintf(stderr, msg, args);
        va_end(args);
    }
}

void do_perror(char *msg)
{
    if (debug) {
        fprintf(stderr, "%s : %s\n", msg, strerror(errno));
    }
}

void my_err(char *msg, ...)                                                                          
{
    va_list args;
    
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
}
