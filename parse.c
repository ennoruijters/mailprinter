#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include "error.h"

int print_pdfs = 0, print_body = 1;

struct header {
	char *name;
	char *body;
};
int print(struct header *hdrs, int nhdr, char *message);
int print_binary(void *message, size_t size);
char *get_message(FILE *fd, char *content_type, const char *upto, const char *cte);

enum { INITIAL_BUFFER_SIZE = 2 };

/* Returns next character if the line is a continuation, EOF otherwise.
 * In the otherwise case, the first character of the next line has been
 * pushed back into the stream.
 */
int continue_line(FILE *fd, int last_char)
{
	int c;
	c = getc(fd);
	if (c == EOF)
		return EOF;
	if (last_char == '\r' && c == '\n') {
		c = getc(fd);
		if (c == EOF)
			return EOF;
	}
	if (c == ' ' || c == '\t') {
		while ( (c = getc(fd)) == ' ' || c == '\t')
			;
		return c;
	}
	ungetc(c, fd);
	return EOF;
}

char *read_header_line(FILE *fd)
{
	char *buf, *tmp;
	size_t buf_size = INITIAL_BUFFER_SIZE, buf_pos = 0;
	
	if (!(buf = malloc(buf_size)))
		return NULL;
	while (1) {
		int c;
		c = getc(fd);
		if (c == EOF) {
			buf[buf_pos] = '\0';
			set_error("Invalid header: unexpected end at %s", buf);
			free(buf);
			errno = EINVAL;
			return NULL;
		}
		if (c == '\r' || c == '\n') {
			c = continue_line(fd, c);
			if (c == EOF)
				break;
		}
		buf[buf_pos++] = c;
		if (buf_pos == buf_size) {
			if (buf_size == SIZE_MAX) {
				free(buf);
				errno = ENOMEM;
				return NULL;
			}
			if (buf_size > (SIZE_MAX / 2))
				buf_size = SIZE_MAX;
			else
				buf_size *= 2;
			tmp = realloc(buf, buf_size);
			if (!tmp) {
				free(buf);
				errno = ENOMEM;
				return NULL;
			}
			buf = tmp;
		}
	}
	buf[buf_pos++] = '\0';
	tmp = realloc(buf, buf_pos);
	if (!tmp) {
		return buf;
	}
	return tmp;
}

/* Returns:
 * 0 if strings are equals (ignoring case)
 * 1 otherwise
 */
int strcmp_nocase(const char *str1, const char *str2)
{
	while (*str1 && *str2) {
		if (toupper(*str1) != toupper(*str2))
			return 1;
		str1++;
		str2++;
	}
	return *str1 != *str2; 
}

int startswith_nocase(const char *haystack, const char *needle)
{
	while (*haystack && *needle) {
		if (toupper(*haystack) != toupper(*needle))
			return 0;
		needle++;
		haystack++;
	}
	if (*needle)
		return 0;
	return 1;
}

char *duplicate_str(const char *str)
{
	char *out;
	out = malloc(strlen(str) + 1);
	if (out)
		strcpy(out, str);
	return out;
}

int parse_headers(FILE *fd, struct header *headers, int nhdr)
{
	char *hdr, *body;
	int i, tmp;

	for (i = 0; i < nhdr; i++)
		headers[i].body = NULL;

	hdr = read_header_line(fd);
	if (!hdr)
		goto err_out;
	while (*hdr) {
		body = strchr(hdr, ':');
		if (!body) {
			set_error("Invalid header line: %s", hdr);
			free(hdr);
			errno = EINVAL;
			goto err_out;
		}
		*body = 0;
		for (i = 0; i < nhdr; i++) {
			if (!strcmp_nocase(headers[i].name, hdr))
				break;
		}
		if (i != nhdr) {
			body++;
			while (*body && (*body == ' ' || *body == '\t'))
				body++;
			headers[i].body = duplicate_str(body);
		}
		free(hdr);
		hdr = read_header_line(fd);
		if (!hdr)
			goto err_out;
	}
	free(hdr);
	return 0;

err_out:
	tmp = errno;
	for (i = 0; i < nhdr; i++)
		free(headers[i].body);
	errno = tmp;
	return -1;
}

char *decode_quot(char *input, size_t *size)
{
	char *ret, *cur_to;
	ret = malloc(strlen(input) + 1);
	if (!ret)
		return NULL;
	cur_to = ret;
	while (input && *input) {
		char *next_eq;
		next_eq = strchr(input, '=');
		if (!next_eq) {
			strcpy(cur_to, input);
			cur_to += strlen(cur_to);
			input = NULL;
		} else {
			memcpy(cur_to, input, next_eq - input);
			cur_to += next_eq - input;
			input = next_eq + 1;
			if (*input == '\r') {
				input++;
				if (*input == '\n')
					input++;
			} else if (*input == '\n') {
				input++;
			} else {
				char *endptr;
				long c;
				char tmp[3] = {0,0,0};
				if (!isalnum(input[0]) || !isalnum(input[1])) {
					*(cur_to++) = '=';
					continue;
				}
				memcpy(tmp, input, 2);
				c = strtol(tmp, &endptr, 16);
				if (*endptr) {
					*(cur_to++) = '=';
					continue;
				}
				*cur_to = c;
				cur_to++;
				input += 2;
			}
		}
	}
	*cur_to = 0;
	if (size)
		*size = cur_to - ret;
	cur_to = realloc(ret, cur_to - ret + 1);
	if (cur_to)
		return cur_to;
	else
		return ret;
}

const char base64_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
unsigned char *decode_base64(char *input, size_t *size)
{
	size_t fake_size = 0;
	uint32_t cur = 0;
	char count = 0;
	unsigned char *ret, *cur_to;
	if (!size)
		size = &fake_size;
	ret = malloc((strlen(input) / 4) * 3 + 1);
	if (!ret)
		ret = (unsigned char *)input;
	cur_to = ret;
	while (*input) {
		char *c;
		c = strchr(base64_alphabet, *(input++));
		if (!c)
			continue;
		if (*c == '=') {
			switch(count) {
			case 2:
				cur_to[0] = cur >> 4;
				cur_to++;
				(*size)++;
				break;
			case 3:
				cur_to[1] = (cur >> 2) % 256;
				cur_to[0] = cur >> 10;
				cur_to += 2;
				(*size) += 2;
				break;
			default:
				break;
			}
			break;
		}
		cur = cur * 64 + (c - base64_alphabet);
		count++;
		if (count == 4) {
			cur_to[2] = cur % 256;
			cur /= 256;
			cur_to[1] = cur % 256;
			cur_to[0] = cur / 256;
			cur_to += 3;
			cur = 0;
			count = 0;
			*size += 3;
		}
	}
	*cur_to = 0;
	return ret;
}

char *decode(char *input, const char *cte, size_t *size)
{
	if (!cte
	    || !strcmp_nocase(cte, "7bit")
	    || !strcmp_nocase(cte, "8bit")
	    || !strcmp_nocase(cte, "binary"))
	{
		if (size)
			*size = strlen(input);
		return input;
	}

	if (!strcmp_nocase(cte, "quoted-printable"))
		return decode_quot(input, size);
	if (!strcmp_nocase(cte, "base64"))
		return (char *)decode_base64(input, size);
	return input;
}

/* Reads the file until the string in 'boundary' has been read or EOF is
 * reached. Check for EOF using feof().
 * If 'boundary' is reached, this string (and any preceding whitespace) is
 * removed from the message.
 */
char *get_message_upto(FILE *fd, const char *boundary, const char *cte,
		       size_t *size)
{
	char *buf, *tmp;
	size_t buf_size = INITIAL_BUFFER_SIZE, buf_pos = 0, blen;
	int c;
	
	if (boundary) {
		blen = strlen(boundary);
		if (!blen)
			boundary = NULL;
	}
	if (!(buf = malloc(buf_size)))
		return NULL;
	while (isspace(c = getc(fd)) && c != EOF)
		;
	if (c != EOF)
		ungetc(c, fd);
	buf[0] = '\n';
	buf_pos = 1;
	while (1) {
		c = getc(fd);
		if (c == EOF)
			break;
		if (c == '\r') {
			c = getc(fd);
			if (c == EOF)
				break;
			if (c != '\n') {
				ungetc(c, fd);
				c = '\n';
			}
		}
		buf[buf_pos++] = c;
		if (buf_pos == buf_size) {
			if (buf_size == SIZE_MAX) {
				free(buf);
				errno = ENOMEM;
				return NULL;
			}
			if (buf_size > (SIZE_MAX / 2))
				buf_size = SIZE_MAX;
			else
				buf_size *= 2;
			tmp = realloc(buf, buf_size);
			if (!tmp) {
				free(buf);
				errno = ENOMEM;
				return NULL;
			}
			buf = tmp;
		}
		if (boundary && buf_pos >= blen) {
			if (!strncmp(boundary, buf + buf_pos - blen, blen)) {
				buf_pos -= blen;
				break;
			}
		}
	}
	while (buf_pos > 0 && isspace(buf[buf_pos - 1]))
		buf_pos--;
	buf[buf_pos++] = '\0';
	tmp = realloc(buf, buf_pos);
	if (!tmp) {
		tmp = buf;
	}
	buf = decode(tmp, cte, size);
	if (buf != tmp)
		free(tmp);
	return buf;
}

char *get_boundary(char *tmp)
{
	char *boundary;
	while (*tmp && !startswith_nocase(tmp, "boundary="))
		tmp++;
	if (!*tmp) {
		set_error("Could not find boundary");
		errno = EINVAL;
		return NULL;
	}
	boundary = tmp + strlen("boundary=");
	if (*boundary == '\"') {
		boundary++;
		tmp = strchr(boundary, '\"');
		if (!tmp) {
			set_error("Unterminated boundary: %s", tmp);
			errno = EINVAL;
			return NULL;
		}
		*tmp = 0;
	} else {
		tmp = boundary;
		while (!isspace(*tmp) && *tmp)
			tmp++;
		*tmp = 0;
	}
	tmp = malloc(strlen("\n--") + strlen(boundary) + 1);
	if (!tmp)
		return NULL;
	strcpy(tmp, "\n--");
	strcat(tmp, boundary);
	return tmp;
}

/* Returns:
 * 0 if *type is now meaningful, -1 otherwise.
 */
int split_mime_type(char *type, char **subtype, char **params)
{
	char *tmp;
	*subtype = NULL;
	*params = NULL;
	if (!type)
		return -1;
	tmp = strchr(type, '/');
	if (!tmp)
		return -1;
	*tmp = '\0';
	tmp++;
	*subtype = tmp;
	while (!isspace(*tmp) && *tmp != ';' && *tmp)
		tmp++;
	if (*tmp)
		*params = tmp + 1;
	*tmp = 0;
	return 0;
}

char *get_mixed_message(FILE *fd, const char *boundary, const char *cte)
{
	char *buf = NULL, *tmp;
	struct header headers[] = {
		{.name="Content-Type"},
		{.name="Content-Disposition"},
		{.name="Content-Transfer-Encoding"}
	};
	int c, stop = 0;
	tmp = get_message_upto(fd, boundary, NULL, NULL);
	free(tmp); /* Explanatory message before the first boundary */
	c = getc(fd);
	while (c != '\n' && c != EOF)
		c = getc(fd);
	while (!stop) {
		const char *this_cte;
		if (parse_headers(fd, headers, 3)) {
			c = errno;
			free(buf);
			errno = c;
			return NULL;
		}
		if (headers[2].body)
			this_cte = headers[2].body;
		else
			this_cte = cte;
		tmp = get_message(fd, headers[0].body, boundary, this_cte);
		if (headers[1].body && strcmp_nocase(headers[1].body, "inline"))
		{
			free(tmp);
			tmp = NULL;
		}
		for (c = 0; c < 3; c++)
			free(headers[c].body);
		if (!buf) {
			buf = tmp;
		} else if (tmp) {
			uint64_t new_siz;
			void *tmp2;
			new_siz = strlen(buf) + 82 + strlen(tmp) + 1;
			if (new_siz > SIZE_MAX) {
				free(buf);
				free(tmp);
				errno = EFBIG;
				return NULL;
			}
			tmp2 = realloc(buf, new_siz);
			if (!tmp2) {
				free(buf);
				free(tmp);
				errno = ENOMEM;
				return NULL;
			}
			buf = tmp2;
			strcat(buf, "\n-------------------------------------------------------------------------------\n");
			strcat(buf, tmp);
			free(tmp);
		}
		while ( (c = getc(fd)) != '\n') {
			if (stop == 1 && c == '-')
				stop = 2;
			if (stop == 1 && c != '-')
				stop = 0;
			if (stop == 0 && c == '-')
				stop = 1;
		}
		if (stop == 1)
			stop = 0;
	}
	return buf;
}

char *get_alternative_message(FILE *fd, const char *boundary, const char *cte)
{
	char *buf = NULL, *tmp;
	struct header headers[] = {
		{.name="Content-Type"},
		{.name="Content-Disposition"},
		{.name="Content-Transfer-Encoding"}
	};
	int c, stop = 0;
	tmp = get_message_upto(fd, boundary, NULL, NULL);
	free(tmp); /* Explanatory message before the first boundary */
	c = getc(fd);
	while (c != '\n' && c != EOF)
		c = getc(fd);
	while (!stop) {
		const char *this_cte;
		if (parse_headers(fd, headers, 3)) {
			c = errno;
			free(buf);
			errno = c;
			return NULL;
		}
		if (headers[2].body)
			this_cte = headers[2].body;
		else
			this_cte = cte;
		tmp = get_message(fd, headers[0].body, boundary, this_cte);
		if (headers[1].body && strcmp_nocase(headers[1].body, "inline"))
		{
			free(tmp);
			for (c = 0; c < 3; c++)
				free(headers[c].body);
			tmp = NULL;
		}
		for (c = 0; c < 3; c++)
			free(headers[c].body);
		if (tmp && !buf) {
			buf = tmp;
		} else {
			free(tmp);
		}
		while ( (c = getc(fd)) != '\n') {
			if (stop == 1 && c == '-')
				stop = 2;
			if (stop == 1 && c != '-')
				stop = 0;
			if (stop == 0 && c == '-')
				stop = 1;
		}
		if (stop == 1)
			stop = 0;
	}
	return buf;
}

char *get_message(FILE *fd, char *content_type, const char *upto,
		  const char *cte)
{
	char *subtype, *boundary, *tmp;
	if (split_mime_type(content_type, &subtype, &boundary) || !subtype)
		return get_message_upto(fd, upto, cte, NULL);
	if (!strcmp_nocase(content_type, "text")
	    && !strcmp_nocase(subtype, "plain"))
	{
		return get_message_upto(fd, upto, cte, NULL);
	}
	else if (!strcmp_nocase(content_type, "application")
	    && !strcmp_nocase(subtype, "pdf")
	    && print_pdfs)
	{
		size_t size;
		char *msg = get_message_upto(fd, upto, cte, &size);
		print_binary(msg, size);
		free(msg);
		return NULL;
	}
	else if (strcmp_nocase(content_type, "multipart"))
	{
		free(get_message_upto(fd, upto, NULL, NULL));
		return NULL;
	}
	if (!(boundary = get_boundary(boundary)))
		return NULL;
	if (!strcmp_nocase(subtype, "mixed")
	    || !strcmp_nocase(subtype, "parallel")
	    || !strcmp_nocase(subtype, "signed"))
	{
		tmp = get_mixed_message(fd, boundary, cte);
		if (upto)
			free(get_message_upto(fd, upto, NULL, NULL));
	}
	else if (!strcmp_nocase(subtype, "alternative"))
	{
		tmp = get_alternative_message(fd, boundary, cte);
		if (upto)
			free(get_message_upto(fd, upto, NULL, NULL));
	}
	else
	{
		free(boundary);
		errno = EBADMSG;
		return NULL;
	}
	free(boundary);
	return tmp;
}

char *parse_subject(char *input)
{
	char *orig, *ret, *tok;
	orig = input;
	if (!startswith_nocase(input, "==print=="))
		return input;
	input += strlen("==print==");
	ret = strchr(input, ':');
	if (ret) {
		*ret = 0;
		ret++;
	} else {
		ret = "";
	}
	tok = strtok(input, "\t ");
	while (tok) {
		if (!strcmp_nocase(tok, "pdf"))
			print_pdfs = 1;
		if (!strcmp_nocase(tok, "nopdf"))
			print_pdfs = 0;
		if (!strcmp_nocase(tok, "body"))
			print_body = 1;
		if (!strcmp_nocase(tok, "nobody"))
			print_body = 0;
		tok = strtok(NULL, "\t ");
	}

	tok = malloc(strlen(ret) + 1);
	if (!tok)
		return orig;
	strcpy(tok, ret);
	free(orig);
	return tok;
}

int print_message(FILE *fd)
{
	struct header headers[] = {
		{.name = "Content-Type"},
		{.name = "Sender"},
		{.name = "Return-path"},
		{.name = "Content-Transfer-Encoding"},
		{.name = "From"},
		{.name = "CC"},
		{.name = "Date"},
		{.name = "Subject"},
	};
	char *message;
	int ret, i;

	ret = parse_headers(fd, headers, sizeof(headers) / sizeof(*headers));
	if (ret)
		return ret;
	if (headers[7].body) {
		headers[7].body = parse_subject(headers[7].body);
	}
	message = get_message(fd, headers[0].body, NULL, headers[8].body);
	if (!message)
		goto out_err;
	if (print_body &&
	    print(headers + 4, sizeof(headers)/sizeof(*headers) - 4, message))
	{
		goto out_err;
	}
	for (i = 0; i < sizeof(headers)/sizeof(*headers); i++)
		free(headers[i].body);
	free(message);
	return 0;
out_err:
	ret = errno;
	for (i = 0; i < sizeof(headers)/sizeof(*headers); i++)
		free(headers[i].body);
	free(message);
	errno = ret;
	return -1;
}

int main(void)
{
	if (print_message(stdin)) {
		fprintf(stderr, "Error: %s\n", strerror(errno));
		fprintf(stderr, "%s\n", get_error());
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}
