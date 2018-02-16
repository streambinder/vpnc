/* IPSec VPN client compatible with Cisco equipment.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>

#include "sysdep.h"
#include "crypto.h"


#define MSG_SIZE 200
void crypto_error_set(crypto_error **error,
                      int code,
                      int in_errno,
                      const char *fmt, ...)
{
	va_list args;

	if (!error)
		return;
	if (*error) {
		fprintf(stderr, "%s: called with non-NULL *error\n", __func__);
		return;
	}

	*error = calloc(1, sizeof(crypto_error));
	if (!*error)
		return;

	(*error)->code = code;
	(*error)->err = in_errno;

	(*error)->msg = malloc(MSG_SIZE);
	if (!(*error)->msg) {
		fprintf(stderr, "%s: not enough memory for error message\n", __func__);
		crypto_error_clear(error);
		return;
	}

	va_start(args, fmt);
	if (vsnprintf((*error)->msg, MSG_SIZE, fmt, args) == -1)
		(*error)->msg[0] = '\0';
	va_end(args);
}

void crypto_error_free(crypto_error *error)
{
	if (error) {
		if (error->msg)
			free(error->msg);
		memset(error, 0, sizeof(crypto_error));
		free(error);
	}
}

void crypto_error_clear(crypto_error **error)
{
	if (error && *error) {
		crypto_error_free(*error);
		*error = NULL;
	}
}

void crypto_call_error(crypto_error *err)
{
	if (err)
		error(err->code, err->err, "%s\n", err->msg);
	else
		error(1, 0, "unknown error");
}

unsigned char *
crypto_read_file(const char *path, size_t *out_len, crypto_error **error)
{
	struct stat st;
	int fd;
	ssize_t bytes_read;
	size_t file_size;
	unsigned char *data = NULL;

	*out_len = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		crypto_error_set(error, 1, errno, "failed to open file '%s'", path);
		return NULL;
	}

	if (fstat(fd, &st) < 0) {
		crypto_error_set(error, 1, errno, "failed to stat file '%s'", path);
		goto out;
	}

	if (st.st_size <= 0 || st.st_size > INT_MAX) {
		crypto_error_set(error, 1, errno, "invalid file '%s' length %ld", path, st.st_size);
		goto out;
	}

	file_size = st.st_size;
	data = malloc(file_size);
	if (!data) {
		crypto_error_set(error, 1, ENOMEM, "not enough memory to read file '%s'", path);
		goto out;
	}

	do {
		bytes_read = read(fd, &(data[*out_len]), (st.st_size - *out_len));
		if (bytes_read < 0) {
			free(data);
			data = NULL;
			*out_len = 0;
			crypto_error_set(error, 1, errno, "failed to read file '%s'", path);
			goto out;
		}
		*out_len += bytes_read;
	} while ((bytes_read > 0) && (*out_len <= file_size));

out:
	close(fd);
	return data;
}

