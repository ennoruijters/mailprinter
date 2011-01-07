#include <stdio.h>
#include "error.h"

struct header {
	char *name;
	char *body;
};

int print(struct header *hdrs, int nhdr, char *message)
{
	FILE *p;
	int i;
	p = popen("lp -t mail", "w");
	if (!p) {
		set_error("Print error");
		return -1;
	}
	for (i = 0; i < nhdr; i++) {
		if (hdrs[i].body)
			fprintf(p, "%s: %s\n", hdrs[i].name, hdrs[i].body);
	}
	for (i = 0; i < 79; i++)
		putc('=', p);
	putc('\n', p);
	fprintf(p, "%s", message);
	pclose(p);
	return 0;
}

int print_binary(void *message, size_t size)
{
	FILE *p;
	p = popen("lp -t attachment", "w");
	if (!p) {
		set_error("Error printing binary");
		return -1;
	}
	fwrite(message, size, 1, p);
	pclose(p);
	return 0;
}
