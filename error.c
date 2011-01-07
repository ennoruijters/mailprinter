#include <stdarg.h>
#include <stdio.h>

#define MAX_MSG_SIZE 4096
static char error_msg[MAX_MSG_SIZE];

void set_error(char *fmt, ...)
{
	va_list argp;
	va_start(argp, fmt);
	vsnprintf(error_msg, MAX_MSG_SIZE, fmt, argp);
	va_end(argp);
}

char *get_error(void)
{
	return error_msg;
}
