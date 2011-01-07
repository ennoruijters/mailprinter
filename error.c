#include <stdarg.h>

#define MAX_MSG_SIZE 4096
static char error_msg[MAX_MSG_SIZE];
static int msg_oom;

void set_error(char *fmt, ...)
{
	va_list argp;
	int size;
	char tmp[1];
	va_start(argp, fmt);
	vsnprintf(error_msg, MAX_MSG_SIZE, fmt, argp);
	va_end(argp);
}

char *get_error(void)
{
	return error_msg;
}
