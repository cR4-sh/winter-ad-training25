#include <fcntl.h>
#include <linux/limits.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define LEN(x) ((sizeof (x)) / (sizeof *(x)))

#define SECRET_SIZE 40
#define PASSWORD_SIZE 40
#define SECRETS_MAX 2048
#define WELCOME "\n\
\n\
    __  ______    _   ____ __ ___ \n\
   /  |/  /   |  / | / / //_//   |\n\
  / /|_/ / /| | /  |/ / ,<  / /| |\n\
 / /  / / ___ |/ /|  / /| |/ ___ |\n\
/_/  /_/_/  |_/_/ |_/_/ |_/_/  |_|\n\
\n\
 /------------------------------------------------------\\\n\
 |        Welcome to the manka service.                 |\n\
 |     Here you can storage secrets in memory           |\n\
 \\------------------------------------------------------/\n"

typedef struct Secret {
	char password[PASSWORD_SIZE];
	char value[SECRET_SIZE];
} Secret;

size_t *secrets_length;
Secret *secrets;

static void *shared_alloc(size_t size) {
	return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

static ssize_t write_cstr(int fd, const char *cstr) {
	return write(fd, cstr, strlen(cstr));
}

static ssize_t read_question(int fd, void *data, size_t data_size, const char *question) {
	ssize_t read_size;
	write_cstr(fd, question);
	read_size = read(fd, data, data_size);
	return read_size;
}

static ssize_t read_or_error(int fd, void *data, size_t data_size,
	const char *question, const char *error) {
	ssize_t read_size;
	read_size = read_question(fd, data, data_size, question);
	if (read_size <= 0) {
		write_cstr(2, error);
		write_cstr(fd, error);
		close(fd);
		return -1;
	}
	return read_size;
}

static int handle_connection(int serv, int client, struct sockaddr_storage addr, socklen_t addr_len) {
	char password[PASSWORD_SIZE] = {0};
	char secret[SECRET_SIZE] = {0};
	char action_str[4] = {0};
	char key[0x20] = {0};
	int action = 0;
	ssize_t read_secret, read_password, read_action;
	char *password_end, *secret_end;
	write_cstr(client, WELCOME);
	write_cstr(client, "List of actions:\n");
	write_cstr(client, "1) Save secret\n");
	write_cstr(client, "2) Get secret\n");
	read_action = read_or_error(client, action_str, sizeof action_str,
		"Enter your action: ", "No action, exiting...\n");
	if (read_action == -1) return -1;
	action = strtol(action_str, &(char *){action_str + read_action}, 10);
	switch (action) {
	case 1: {
		char buffer[0x100];
		size_t secret_id = *secrets_length;
		*secrets_length = (*secrets_length + 1) % SECRETS_MAX;
		read_secret = read_or_error(client, secret, sizeof secret,
			"Enter secret: ", "No secret, exiting...\n");
		if (read_secret == -1) return -1;
		secret_end = strchr(secret, '\n');
		if (secret_end) {
			read_secret = secret_end - secret;
		}
		read_password = read_or_error(client, password, sizeof secret,
			"Enter password: ", "Must be password\n");
		if (read_password == -1) return -1;
		password_end = strchr(password, '\n');
		if (password_end) {
			read_password = password_end - password;
		}
		memcpy(secrets[secret_id].value, secret, read_secret);
		memcpy(secrets[secret_id].password, password, read_password);
		snprintf(buffer, sizeof buffer, "Your key is: %p\n", &secrets[secret_id]);
		write_cstr(client, buffer);
		close(client);
		return 0;
	} break;
	case 2: {
		Secret *secret;
		ssize_t read_key;
		read_key = read_or_error(client, key, sizeof key,
			"Enter key: ", "Error, empty key\n");
		if (read_secret == -1) return -1;
		secret = (Secret *)strtoll(key, &(char *){key + read_key}, 16);
		read_password = read_or_error(client, password, sizeof password,
			"Enter password: ", "Must be password\n");
		if (read_password == -1) return -1;
		password_end = strchr(password, '\n');
		if (password_end) {
			read_password = password_end - password;
		}
		if (memcmp(secret->password, password, read_password) == 0) {
			write_cstr(client, "Corrent, here's your secret: ");
			write(client, secret->value, SECRET_SIZE);
			write_cstr(client, "\n");
		} else {
			write_cstr(client, "Wrong password!\n");
		}
		close(client);
		return 0;
	} break;
	case 3: {
		char path[PATH_MAX] = {0};
		ssize_t read_path, read_offset, read_rsize;
		char offset_str[0x20] = {0};
		char rsize_str[0x20] = {0};
		size_t offset = 0;
		size_t rsize = 0;
		char *path_end;
		char buffer[0x100];
		int fd;
		read_path = read_or_error(client, path, sizeof path,
			"Enter file path: ", "Empty path\n");
		if (read_path == -1) return -1;
		path_end = strchr(path, '\n');
		if (path_end) {
			*path_end = '\0';
		}
		read_offset = read_or_error(client, offset_str, sizeof offset_str,
			"Enter offset: ", "No offset provided\n");
		if (read_action == -1) return -1;
		offset = strtoll(offset_str, &(char *){offset_str + read_offset}, 10);
		read_rsize = read_or_error(client, rsize_str, sizeof rsize_str,
			"Enter read size: ", "No read size provided\n");
		if (read_rsize == -1) return -1;
		rsize = strtoll(rsize_str, &(char *){rsize_str + read_rsize}, 10);
		if (rsize == 0 || rsize > 0x100) {
			write_cstr(client, "Wrong file size (max 1024)\n");
			close(client);
			return -1;
		}
		fd = open(path, O_RDONLY);
		if (fd == -1) {
			write_cstr(client, "File doesn't exists!\n");
			close(client);
			return -1;
		}
		write_cstr(client, "Your file is: ");
		lseek(fd, offset, SEEK_SET);
		read(fd, buffer, rsize);
		write(client, buffer, rsize);
		write_cstr(client, "\nEnd of the file");
		close(client);
		return 0;
	} break;
	default: {
		write_cstr(client, "Unknown action\n");
		close(client);
		return -1;
	} break;
	}
	return 0;
}

extern int main(void) {
	int serv;
	struct sockaddr_in addr = (struct sockaddr_in) {
		.sin_family = AF_INET,
		.sin_port = htons(7191),
		.sin_addr.s_addr = htonl(INADDR_ANY),
	};
	secrets_length = shared_alloc(sizeof *secrets * SECRETS_MAX + sizeof *secrets_length);
	secrets = (Secret *)(secrets_length + sizeof *secrets_length);
	serv = socket(AF_INET, SOCK_STREAM, 0);
	if (serv == -1) {
		perror("socket");
		return -1;
	}
	if (setsockopt(serv, SOL_SOCKET, SO_REUSEPORT, &(int){1},
		sizeof (int)) == -1) {
		perror("setsockopt");
		return -1;
	}
	if (bind(serv, (struct sockaddr*)&addr, sizeof addr) == -1) {
		perror("bind");
		return -1;
	}
	if (listen(serv, 3) == -3) {
		perror("listen");
		return -1;
	}
	for (;;) {
		waitpid(-1, NULL, WNOHANG);
		struct sockaddr_storage inaddr;
		socklen_t inaddr_len;
		int client;
		pid_t pid;
		client = accept(serv, (struct sockaddr *)&inaddr,
			&inaddr_len);
		if (client == -1) {
			perror("accept");
			continue;
		}
		pid = fork();
		if (pid == -1) {
			perror("fork");
			continue;
		} else if (pid != 0) {
			close(client);
			continue;
		}
		return handle_connection(serv, client, inaddr, inaddr_len);
	}
	return 0;
}