#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define ERR_MSG "An error was reported to the system logger.\n"

#define crit(fmt, ...) \
	{ \
		dprintf(STDERR_FILENO, ERR_MSG); \
		syslog(LOG_CRIT, fmt ": %s", ##__VA_ARGS__, strerror(errno)); \
	}

#define err(fmt, ...) \
	{ \
		dprintf(STDERR_FILENO, ERR_MSG); \
		syslog(LOG_ERR, fmt, ##__VA_ARGS__); \
	}

#define notice(fmt, ...) \
	syslog(LOG_NOTICE, fmt, ##__VA_ARGS__)

#define info(fmt, ...) \
	syslog(LOG_INFO, fmt, ##__VA_ARGS__)

#define debug(fmt, ...) \
	syslog(LOG_DEBUG, "%s: " fmt, __func__, ##__VA_ARGS__)

#define user(fmt, ...) \
	{ \
		dprintf(STDERR_FILENO, fmt "\n", ##__VA_ARGS__); \
		syslog(LOG_DEBUG, ">&2 " fmt, ##__VA_ARGS__); \
	}

#define print(fmt, ...) \
	dprintf(STDOUT_FILENO, fmt, ##__VA_ARGS__)

struct command;
struct directory;
struct link;
struct power;
struct remote;
struct tty;

struct unit {
	const char *name;
	const char *description;

	enum {
		UNIT_TYPE_NONE = 0,
		UNIT_TYPE_COMMAND,
		UNIT_TYPE_DIRECTORY,
		UNIT_TYPE_LINK,
		UNIT_TYPE_POWER,
		UNIT_TYPE_REMOTE,
		UNIT_TYPE_TTY,
	} type;

	union {
		struct command *command;
		struct directory *directory;
		struct link *link;
		struct power *power;
		struct remote *remote;
		struct tty *tty;
	};

	struct unit *next;
};

struct command {
	const char *path;
	const char *synopsis;
	int (*builtin)(int argc, char *argv[]);
};

struct directory {
	const char *path;
};

struct link {
	const char *local_interface;
	const char *remote_interface;
	const struct remote *remote;
};

struct power {
	const char *hostname;
	const char *port;

	/* TODO: make power drivers "discrete" commands? */
	int (*driver)(const struct power *power, const char *action);
};

struct remote {
	const char *hostname;
	const char *password;
	const char *user;
	const struct directory *directory;
	const struct power *power;
	const struct tty *tty;
};

struct tty {
	const char *baudrate;
	const char *device;
};

static struct unit head;

static const struct unit *get_unit_by_name(const char *name)
{
	const struct unit *unit;

	for (unit = head.next; unit; unit = unit->next)
		if (unit->name && strcmp(unit->name, name) == 0)
			return unit;

	return NULL;
}

static const struct command *get_command(const struct unit *unit)
{
	if (unit->type == UNIT_TYPE_COMMAND)
		return unit->command;

	return NULL;
}

static const struct link *get_link(const struct unit *unit)
{
	if (unit->type == UNIT_TYPE_LINK)
		return unit->link;

	return NULL;
}

static const struct remote *get_remote(const struct unit *unit)
{
	const struct link *link;

	if (unit->type == UNIT_TYPE_REMOTE)
		return unit->remote;

	link = get_link(unit);
	if (link)
		return link->remote;

	return NULL;
}

static const struct power *get_power(const struct unit *unit)
{
	const struct remote *remote;

	if (unit->type == UNIT_TYPE_POWER)
		return unit->power;

	remote = get_remote(unit);
	if (remote)
		return remote->power;

	return NULL;
}

static const struct tty *get_tty(const struct unit *unit)
{
	const struct remote *remote;

	if (unit->type == UNIT_TYPE_TTY)
		return unit->tty;

	remote = get_remote(unit);
	if (remote)
		return remote->tty;

	return NULL;
}

static const struct directory *get_directory(const struct unit *unit)
{
	const struct remote *remote;

	if (unit->type == UNIT_TYPE_DIRECTORY)
		return unit->directory;

	remote = get_remote(unit);
	if (remote)
		return remote->directory;

	return NULL;
}

static const struct command *get_command_by_name(const char *name)
{
	const struct unit *unit;

	unit = get_unit_by_name(name);
	if (!unit)
		return NULL;

	return get_command(unit);
}

static const struct remote *get_remote_by_name(const char *name)
{
	const struct unit *unit;

	unit = get_unit_by_name(name);
	if (!unit)
		return NULL;

	return get_remote(unit);
}

static const struct directory *get_directory_by_name(const char *name)
{
	const struct unit *unit;

	unit = get_unit_by_name(name);
	if (!unit)
		return NULL;

	return get_directory(unit);
}

static const struct power *get_power_by_name(const char *name)
{
	const struct unit *unit;

	unit = get_unit_by_name(name);
	if (!unit)
		return NULL;

	return get_power(unit);
}

static const struct tty *get_tty_by_name(const char *name)
{
	const struct unit *unit;

	unit = get_unit_by_name(name);
	if (!unit)
		return NULL;

	return get_tty(unit);
}

static const char *unit_name(const struct unit *unit)
{
	return unit->name ? : "<unamed unit>";
}

static const char *unit_type(const struct unit *unit)
{
	switch (unit->type) {
	case UNIT_TYPE_COMMAND:
		return "Command";
	case UNIT_TYPE_DIRECTORY:
		return "Directory";
	case UNIT_TYPE_LINK:
		return "Link";
	case UNIT_TYPE_POWER:
		return "Power";
	case UNIT_TYPE_REMOTE:
		return "Remote";
	case UNIT_TYPE_TTY:
		return "TTY";
	default:
		return "<undefined type>";
	}
}

static int builtin_exec(int argc, char *argv[])
{
	char *exec_argv[argc + 1];
	int status;
	pid_t pid;
	int i;

	for (i = 0; i < argc; i++) {
		exec_argv[i] = argv[i];
		debug("arg%d: %s", i, exec_argv[i]);
	}

	exec_argv[i] = NULL;

	pid = fork();
	if (pid == -1) {
		crit("fork");
		return 1;
	}

	if (pid == 0) {
		if (execv(exec_argv[0], exec_argv) == -1) {
			if (errno == ENOENT)
				status = 127;
			else
				status = 126;

			_exit(status);
		}
	}

	for (;;) {
		if (waitpid(pid, &status, WCONTINUED | WUNTRACED) == -1) {
			if (errno == EINTR)
				continue;

			crit("wait %d", pid);
			return 1;
		}

		if (WIFEXITED(status)) {
			status = WEXITSTATUS(status);

			if (status == 127)
				errno = ENOENT;
			else if (status == 126)
				errno = EACCES;
			else
				errno = 0;

			if (errno)
				crit("execv %s", exec_argv[0]);

			info("Child %d exited with code %d", pid, status);

			return status;
		}

		if (WIFSIGNALED(status)) {
			err("Child %d killed with signal %d", pid, WTERMSIG(status));
			return 1;
		}

		if (WIFSTOPPED(status)) {
			info("Child %d stopped with signal %d", pid, WSTOPSIG(status));
			continue;
		}

		if (WIFCONTINUED(status)) {
			info("Child %d continued", pid);
			continue;
		}

		/* Unlikely... */
		err("Unexpected status (0x%x)", status);
		break;
	}

	return 1;
}

static int power_synaccess(const struct power *power, const char *action)
{
	char *argv[] = { "bin/power-synaccess", "-H", (char *) power->hostname, NULL, (char *) power->port };
	int argc = sizeof argv / sizeof argv[0];

	if (!power->hostname) {
		err("Undefined power hostname.");
		return 1;
	}

	if (strcmp(action, "poweroff") == 0) {
		argv[3] = "-p";
	} else if (strcmp(action, "poweron") == 0) {
		argv[3] = "-o";
	} else if (strcmp(action, "reboot") == 0) {
		argv[3] = "-r";
	} else {
		user("Unsupported command %s.", action);
		return 1;
	}

	return builtin_exec(argc, argv);
}

static int power_webrelay(const struct power *power, const char *action)
{
	char *argv[] = { "bin/power-webrelay", "-H", (char *) power->hostname, NULL };
	int argc = sizeof argv / sizeof argv[0];

	if (!power->hostname) {
		err("Undefined power hostname.");
		return 1;
	}

	if (power->port)
		info("Ignoring power port.");

	if (strcmp(action, "poweroff") == 0) {
		argv[3] = "-p";
	} else if (strcmp(action, "poweron") == 0) {
		argv[3] = "-o";
	} else if (strcmp(action, "reboot") == 0) {
		argv[3] = "-r";
	} else {
		user("Unsupported command %s.", action);
		return 1;
	}

	return builtin_exec(argc, argv);
}

static int power_exec(const struct power *power, const char *action)
{
	if (!power->driver) {
		err("Power driver required.");
		return 1;
	}

	return power->driver(power, action);
}

static int tty_exec(const struct tty *tty)
{
	char *argv[] = { "bin/tty-dtach-picocom", (char *) tty->device, (char *) tty->baudrate };
	int argc = sizeof argv / sizeof argv[0];

	if (!argv[1]) {
		err("TTY device required.");
		return 1;
	}

	/* Baudrate is optional */
	if (!argv[2])
		argc--;

	return builtin_exec(argc, argv);
}

static int remote_exec(const struct remote *remote, int argc, char *argv[])
{
	if (remote->hostname) {
		int ssh_argc = 12; /* Max SSH args (without user command) */
		char *ssh_argv[ssh_argc + argc];
		int i;

		ssh_argc = 0;

		if (remote->password) {
			ssh_argv[ssh_argc++] = "/usr/bin/sshpass";
			ssh_argv[ssh_argc++] = "-p";
			ssh_argv[ssh_argc++] = (char *) remote->password;
		}

		ssh_argv[ssh_argc++] = "/usr/bin/ssh";
		ssh_argv[ssh_argc++] = "-o";
		ssh_argv[ssh_argc++] = "StrictHostKeyChecking=no";
		ssh_argv[ssh_argc++] = "-o";
		ssh_argv[ssh_argc++] = "UserKnownHostsFile=/dev/null";

		if (remote->user) {
			ssh_argv[ssh_argc++] = "-l";
			ssh_argv[ssh_argc++] = (char *) remote->user;
		}

		ssh_argv[ssh_argc++] = (char *) remote->hostname;
		ssh_argv[ssh_argc++] = "--";

		for (i = 0; i < argc; i++)
			ssh_argv[ssh_argc++] = argv[i];

		return builtin_exec(ssh_argc, ssh_argv);
	}

	/* Fallback to serial driver */
	if (remote->tty) {
		user("Serial driver not implemented.");
		return 1;
	}

	user("No SSH or console access to remote.");
	return 1;
}

static int command_exec(const struct command *command, int argc, char *argv[])
{
	int i;

	for (i = 0; i < argc; i++)
		debug("arg%d: %s", i, argv[i]);

	if (!command->builtin) {
		err("No builtin for command %s.", argv[0]);
		return 1;
	}

	/* If a pathname is provided, override the command name */
	if (command->path)
		argv[0] = (char *) command->path;

	return command->builtin(argc, argv);
}

static int builtin_help(int argc, char *argv[])
{
	const struct command *command;
	const struct unit *unit;
	int ret = 0;
	int i;

	if (argc < 2) {
		/* Describe all commands */
		for (unit = head.next; unit; unit = unit->next) {
			if (get_command(unit)) {
				print("%s", unit_name(unit));
				if (unit->description)
					print(" - %s", unit->description);
				print("\n");
			}
		}

		return 0;
	}

	/* Print synopsis for each command argument */
	for (i = 1; i < argc; i++) {
		command = get_command_by_name(argv[i]);
		if (command) {
			print("%s\n", command->synopsis ? : argv[i]);
		} else {
			user("Unknown command %s.", argv[i]);
			ret += 1;
		}
	}

	return ret;
}

static int builtin_power(int argc, char *argv[])
{
	const struct power *power;
	const struct unit *unit;
	int ret = 0;
	int i;

	if (argc > 1) {
		/* Apply command for each argument */
		for (i = 1; i < argc; i++) {
			power = get_power_by_name(argv[i]);
			if (power) {
				ret += power_exec(power, argv[0]);
			} else {
				user("No power unit attached to %s.", argv[i]);
				ret += 1;
			}
		}
	} else if (strcmp(argv[0], "power") == 0) {
		/* List units with a power unit attached to them */
		for (unit = head.next; unit; unit = unit->next)
			if (get_power(unit))
				print("%s (%s)\n", unit_name(unit), unit_type(unit));
	} else {
		/* Apply shortcut command to all power units */
		for (unit = head.next; unit; unit = unit->next)
			if (unit->type == UNIT_TYPE_POWER && unit->power)
				ret += power_exec(unit->power, argv[0]);
	}

	return ret;
}

static int builtin_remote(int argc, char *argv[])
{
	const struct remote *remote;
	const struct unit *unit;
	int i;

	if (argc < 2) {
		/* List remote units */
		for (unit = head.next; unit; unit = unit->next)
			if (get_remote(unit))
				print("%s (%s)\n", unit_name(unit), unit_type(unit));

		return 0;
	}

	/* Connect to remote unit (and forward optional command) */
	remote = get_remote_by_name(argv[1]);
	if (!remote) {
		user("No remote unit attached to %s.", argv[1]);
		return 1;
	}

	return remote_exec(remote, argc - 2, argv + 2);
}

static int builtin_scp(int argc, char *argv[])
{
	bool r = false, d = false, t = false, f = false;
	const struct directory *directory;
	const struct unit *unit;
	int scp_argc = 5; /* Max scp args */
	char *scp_argv[scp_argc];
	int i;

	if (argc < 2) {
		/* List directory units */
		for (unit = head.next; unit; unit = unit->next)
			if (get_directory(unit))
				print("%s (%s)\n", unit_name(unit), unit_type(unit));

		return 0;
	}

	for (i = 1; i < argc - 1; i++) {
		if (strcmp(argv[i], "-r") == 0) {
			r = true;
		} else if (strcmp(argv[i], "-d") == 0) {
			d = true;
		} else if (strcmp(argv[i], "-t") == 0) {
			t = true;
		} else if (strcmp(argv[i], "-f") == 0) {
			f = true;
		} else {
			err("Unsupported option %s.", argv[i]);
			return 1;
		}
	}

	directory = get_directory_by_name(argv[i]);
	if (!directory || !directory->path) {
		user("No directory unit attached to %s.", argv[i]);
		return 1;
	}

	if (!t || f) {
		user("Only uploading to %s is supported.", argv[i]);
		return 1;
	}

	scp_argc = 0;
	scp_argv[scp_argc++] = "/bin/scp";
	if (r)
		scp_argv[scp_argc++] = "-r";
	if (d)
		scp_argv[scp_argc++] = "-d";
	scp_argv[scp_argc++] = "-t";
	scp_argv[scp_argc++] = (char *) directory->path;

	return builtin_exec(scp_argc, scp_argv);
}

static int builtin_tty(int argc, char *argv[])
{
	const struct unit *unit;
	const struct tty *tty;

	if (argc < 2) {
		/* List TTY units */
		for (unit = head.next; unit; unit = unit->next)
			if (get_tty(unit))
				print("%s (%s)\n", unit_name(unit), unit_type(unit));

		return 0;
	}

	tty = get_tty_by_name(argv[1]);
	if (!tty) {
		user("No TTY unit attached to %s.", argv[1]);
		return 1;
	}

	return tty_exec(tty);
}

static int read_string(int fd, char *buf, size_t size)
{
	ssize_t n;

	n = read(fd, buf, size);
	if (n == -1) {
		crit("read %d", fd);
		return 1;
	}

	if (n == size) {
		err("Content exceeds %d chars.", size);
		return 1;
	}

	buf[n] = '\0';

	return 0;
}

static int parse_command(char *buf)
{
	const struct command *command;
	char **reloc, **argv = NULL;
	int ret, argc = 0;

	notice("+ %s", buf);

	while (*buf) {
		/* End of arg */
		if (isspace(*buf)) {
			*buf++ = '\0';
			continue;
		}

		/* Beginning of arg */
		reloc = realloc(argv, ++argc * sizeof(char *));
		if (!reloc) {
			crit("realloc");
			free(argv);
			return 1;
		}
		argv = reloc;
		argv[argc - 1] = buf;

		/* Walk content of arg */
		while (*buf && !isspace(*buf))
			buf++;
	}

	if (!argv)
		return 0;

	command = get_command_by_name(argv[0]);
	if (!command) {
		user("Unknown command %s, try 'help'.", argv[0]);
		free(argv);
		return 1;
	}

	ret = command_exec(command, argc, argv);
	free(argv);
	return ret;
}

static int parse_input(char *buf)
{
	char *begin, *end = buf;
	int ret = 0;

	for (;;) {
		begin = end;

		while (isspace(*begin))
			begin++;

		if (*begin == '\0')
			break;

		if (*begin == '#') {
			end = strchr(begin, '\n');
			if (!end)
				break;

			end++;
		} else {
			end = begin;
			while (*end) {
				if (*end == ';' || *end == '\n') {
					*end++ = '\0';
					break;
				}
				end++;
			}

			ret += parse_command(begin);
		}
	}

	return ret;
}

static int read_input(int fd)
{
	char buf[BUFSIZ];
	int ret;

	ret = read_string(fd, buf, sizeof(buf));
	if (ret)
		return 1;

	return parse_input(buf);
}

static int interactive_shell(const char *prompt)
{
	char buf[BUFSIZ];
	int rs, rc = 0;

	/* Greetings */
	print("Welcome to Kernera restricted shell!\n");
	print("Try 'help' or ^D to quit.\n");

	for (;;) {
		if (rc)
			print("[%d] %s", rc, prompt);
		else
			print("%s", prompt);

		rs = read_string(STDIN_FILENO, buf, sizeof(buf));
		if (rs) {
			rc += rs;
			break;
		}

		if (!*buf) {
			print("\n");
			break;
		}

		rc += parse_input(buf);
	}

	return rc;
}

static struct unit *insert(int type)
{
	struct unit *unit, *tail;

	unit = calloc(1, sizeof(struct unit));
	if (!unit) {
		crit("calloc");
		return NULL;
	}

	unit->type = type;

	switch (type) {
	case UNIT_TYPE_NONE:
		break;
	case UNIT_TYPE_COMMAND:
		unit->command = calloc(1, sizeof(struct command));
		if (!unit->command) {
			crit("calloc");
			free(unit);
			unit = NULL;
		}
		break;
	case UNIT_TYPE_DIRECTORY:
		unit->directory = calloc(1, sizeof(struct directory));
		if (!unit->directory) {
			crit("calloc");
			free(unit);
			unit = NULL;
		}
		break;
	case UNIT_TYPE_LINK:
		unit->link = calloc(1, sizeof(struct link));
		if (!unit->link) {
			crit("calloc");
			free(unit);
			unit = NULL;
		}
		break;
	case UNIT_TYPE_POWER:
		unit->power = calloc(1, sizeof(struct power));
		if (!unit->power) {
			crit("calloc");
			free(unit);
			unit = NULL;
		}
		break;
	case UNIT_TYPE_REMOTE:
		unit->remote = calloc(1, sizeof(struct remote));
		if (!unit->remote) {
			crit("calloc");
			free(unit);
			unit = NULL;
		}
		break;
	case UNIT_TYPE_TTY:
		unit->tty = calloc(1, sizeof(struct tty));
		if (!unit->tty) {
			crit("calloc");
			free(unit);
			unit = NULL;
		}
		break;
	default:
		err("Undefined type.");
		free(unit);
		unit = NULL;
		break;
	}

	tail = &head;
	while (tail->next)
		tail = tail->next;

	tail->next = unit;

	return unit;
}

static void delete(void)
{
	struct unit *unit, *next;

	unit = head.next;

	while (unit) {
		switch (unit->type) {
		case UNIT_TYPE_COMMAND:
			free(unit->command);
			break;
		case UNIT_TYPE_DIRECTORY:
			free(unit->directory);
			break;
		case UNIT_TYPE_LINK:
			free(unit->link);
			break;
		case UNIT_TYPE_POWER:
			free(unit->power);
			break;
		case UNIT_TYPE_REMOTE:
			free(unit->remote);
			break;
		case UNIT_TYPE_TTY:
			free(unit->tty);
			break;
		}

		next = unit->next;
		free(unit);
		unit = next;
	}
}

static int open_config(const char *path, char *buf, size_t size)
{
	struct unit *unit = NULL;
	char *begin = buf;
	char *end, *prop;
	ssize_t n = 0;
	int type;
	int ret;
	int fd;

	info("Reading config %s", path);

	fd = open(path, O_RDONLY);
	if (fd == -1) {
		crit("open %s", path);
		return 1;
	}

	ret = read_string(fd, buf, size);
	if (ret)
		return ret;

	for (;;) {
		n++;
		end = strchr(begin, '\n');
		if (!end) {
			err("%s:%d: No newline terminator.", path, n);
			ret += 1;
			return ret; /* Fatal */
		}

		*end = '\0';

		switch (*begin) {
		case '\0':
		case '#':
			break;
		case '[':
			if (strcmp(begin, "[Command]") == 0) {
				type = UNIT_TYPE_COMMAND;
			} else if (strcmp(begin, "[Directory]") == 0) {
				type = UNIT_TYPE_DIRECTORY;
			} else if (strcmp(begin, "[Link]") == 0) {
				type = UNIT_TYPE_LINK;
			} else if (strcmp(begin, "[Power]") == 0) {
				type = UNIT_TYPE_POWER;
			} else if (strcmp(begin, "[Remote]") == 0) {
				type = UNIT_TYPE_REMOTE;
			} else if (strcmp(begin, "[TTY]") == 0) {
				type = UNIT_TYPE_TTY;
			} else {
				err("%s:%d: Poorly formatted or bad section %s.", path, n, begin);
				ret += 1;
				break;
			}

			unit = insert(type);
			if (!unit) {
				ret += 1;
				return ret; /* Fatal */
			}

			break;
		default:
			if (!unit) {
				err("%s:%d: garbage line %s.", path, n, begin);
				ret += 1;
				break;
			}

			prop = begin;
			begin = strchr(prop, '=');
			if (!begin) {
				err("%s:%d: Poorly formatted property %s.", path, n, prop);
				ret += 1;
				break;
			}

			*begin++ = '\0';

			/* Common unit properties */
			if (strcmp(prop, "Name") == 0) {
				if (get_unit_by_name(begin)) {
					err("%s:%d: Unit %s already exists.", path, n, begin);
					ret += 1;
				}
				unit->name = begin;
				break;
			}

			if (strcmp(prop, "Description") == 0) {
				unit->description = begin;
				break;
			}

			/* Type-specific properties */
			switch (unit->type) {
			case UNIT_TYPE_COMMAND:
				if (strcmp(prop, "Path") == 0) {
					unit->command->path = begin;
					unit->command->builtin = builtin_exec;
				} else if (strcmp(prop, "Synopsis") == 0) {
					unit->command->synopsis = begin;
				} else {
					err("%s:%d: Unknown command property %s.", path, n, prop);
					ret += 1;
				}
				break;
			case UNIT_TYPE_DIRECTORY:
				if (strcmp(prop, "Path") == 0) {
					unit->directory->path = begin;
				} else {
					err("%s:%d: Unknown directory property %s.", path, n, prop);
					ret += 1;
				}
				break;
			case UNIT_TYPE_LINK:
				if (strcmp(prop, "LocalInterface") == 0) {
					unit->link->local_interface = begin;
				} else if (strcmp(prop, "RemoteInterface") == 0) {
					unit->link->remote_interface = begin;
				} else if (strcmp(prop, "Remote") == 0) {
					unit->link->remote = get_remote_by_name(begin);
					if (!unit->link->remote) {
						err("%s:%d: Unknown remote unit %s.", path, n, begin);
						ret += 1;
					}
				} else {
					err("%s:%d: Unknown link property %s.", path, n, prop);
					ret += 1;
				}
				break;
			case UNIT_TYPE_POWER:
				if (strcmp(prop, "Driver") == 0) {
					if (strcmp(begin, "synaccess") == 0) {
						unit->power->driver = power_synaccess;
					} else if (strcmp(begin, "webrelay") == 0) {
						unit->power->driver = power_webrelay;
					} else {
						err("%s:%d: Unknown power type %s.", path, n, begin);
						ret += 1;
					}
				} else if (strcmp(prop, "Hostname") == 0) {
					unit->power->hostname = begin;
				} else if (strcmp(prop, "Port") == 0) {
					unit->power->port = begin;
				} else {
					err("%s:%d: Unknown power property %s.", path, n, prop);
					ret += 1;
				}
				break;
			case UNIT_TYPE_REMOTE:
				if (strcmp(prop, "Hostname") == 0) {
					unit->remote->hostname = begin;
				} else if (strcmp(prop, "Password") == 0) {
					unit->remote->password = begin;
				} else if (strcmp(prop, "User") == 0) {
					unit->remote->user = begin;
				} else if (strcmp(prop, "Power") == 0) {
					unit->remote->power = get_power_by_name(begin);
					if (!unit->remote->power) {
						err("%s:%d: Unknown power unit %s.", path, n, begin);
						ret += 1;
					}
				} else if (strcmp(prop, "TTY") == 0) {
					unit->remote->tty = get_tty_by_name(begin);
					if (!unit->remote->tty) {
						err("%s:%d: Unknown TTY unit %s.", path, n, begin);
						ret += 1;
					}
				} else if (strcmp(prop, "Directory") == 0) {
					unit->remote->directory = get_directory_by_name(begin);
					if (!unit->remote->directory) {
						err("%s:%d: Unknown directory unit %s.", path, n, begin);
						ret += 1;
					}
				} else {
					err("%s:%d: Unknown remote property %s.", path, n, prop);
					ret += 1;
				}
				break;
			case UNIT_TYPE_TTY:
				if (strcmp(prop, "Device") == 0) {
					unit->tty->device = begin;
				} else if (strcmp(prop, "Baudrate") == 0) {
					unit->tty->baudrate = begin;
				} else {
					err("%s:%d: Unknown TTY property %s.", path, n, prop);
					ret += 1;
				}
				break;
			default:
				err("%s:%d: Property %s outside of a known section.", path, n, prop);
				ret += 1;
				break;
			}

			break;
		}

		begin = end + 1;
		if (*begin == '\0')
			break;
	}

	return ret;
}

struct builtin_command {
	const char *name;
	const char *description;
	const char *synopsis;
	int (*builtin)(int argc, char *argv[]);
};

static const struct builtin_command command_help = {
	.name = "help",
	.builtin = builtin_help,
	.description = "List or describe command(s)",
	.synopsis = "help [<command>...]",
};

static const struct builtin_command command_power = {
	.name = "power",
	.description = "List power compatible units",
	.builtin = builtin_power,
};

static const struct builtin_command command_poweron = {
	.name = "poweron",
	.description = "Power on some or all power units",
	.synopsis = "poweron [<unit>...]",
	.builtin = builtin_power,
};

static const struct builtin_command command_poweroff = {
	.name = "poweroff",
	.description = "Power off some or all power units",
	.synopsis = "poweroff [<unit>...]",
	.builtin = builtin_power,
};

static const struct builtin_command command_reboot = {
	.name = "reboot",
	.description = "Reboot some or all power units",
	.synopsis = "reboot [<unit>...]",
	.builtin = builtin_power,
};

static const struct builtin_command command_remote = {
	.name = "remote",
	.description = "List remote units or connect to a remote host unit",
	.synopsis = "remote [<unit> [<command>...]]",
	.builtin = builtin_remote,
};

static const struct builtin_command command_ssh = {
	.name = "ssh",
	.description = "Alias for remote",
	.builtin = builtin_remote,
};

static const struct builtin_command command_scp = {
	.name = "scp",
	.description = "Adapter for file transfer over SSH",
	.builtin = builtin_scp,
};

static const struct builtin_command command_tty = {
	.name = "tty",
	.description = "Access a TTY unit",
	.synopsis = "tty <unit>",
	.builtin = builtin_tty,
};

static const struct builtin_command builtin_commands[] = {
	command_help,
	command_power,
	command_poweron,
	command_poweroff,
	command_reboot,
	command_remote,
	command_ssh,
	command_scp,
	command_tty,
	NULL
};

static char config[BUFSIZ];

static int load_config(void)
{
	struct unit *unit;
	int i;

	if (atexit(delete))
		return 1;

	for (i = 0; builtin_commands[i].name; i++) {
		unit = insert(UNIT_TYPE_COMMAND);
		if (!unit)
			return 1;

		unit->name = builtin_commands[i].name;
		unit->description = builtin_commands[i].description;
		unit->command->builtin = builtin_commands[i].builtin;
		unit->command->synopsis = builtin_commands[i].synopsis;
	}

	return open_config(".krshrc", config, sizeof(config));
}

static void bye(void)
{
	info("Closing shell session.");
	closelog();
}

static int init(void)
{
	openlog(NULL, LOG_PID, LOG_USER);
	info("Opening shell session.");

	if (atexit(bye))
		return 1;

	if (load_config())
		return 1;

	return 0;
}

int main(int argc, char *argv[])
{
	bool command_string = false;
	bool standard_input = false;
	bool interactive = false;
	bool login = false;
	int fd;
	int c;

	if (init())
		return EXIT_FAILURE;

	/* Unused */
	if (**argv == '-')
		login = true;

	for (c = 0; c < argc; c++)
		debug("arg%d: %s", c, argv[c]);

	while (c = getopt(argc, argv, "cis:"), c != -1) {
		switch (c) {
		case 'c':
			command_string = true;
			break;
		case 's':
			standard_input = true;
			break;
		case 'i':
			interactive = true;
			break;
		default:
			user("%s: try command 'help'.", argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (argc - optind == 0)
		standard_input = true;

	if (standard_input && isatty(STDIN_FILENO))
		interactive = true;

	if (command_string) {
		if (argc - optind == 0) {
			user("Missing command string.");
			return EXIT_FAILURE;
		}

		if (argc - optind > 1) {
			user("Overriding argv is not supported.");
			return EXIT_FAILURE;
		}

		if (parse_input(argv[optind]))
			return EXIT_FAILURE;
	} else if (standard_input) {
		if (argc - optind > 0) {
			user("Overriding argv is not supported.");
			return EXIT_FAILURE;
		}

		if (interactive) {
			if (interactive_shell("krsh> "))
				return EXIT_FAILURE;
		} else {
			if (read_input(STDIN_FILENO))
				return EXIT_FAILURE;
		}
	} else {
		if (argc - optind == 0) {
			user("Missing command file.");
			return EXIT_FAILURE;
		}

		if (argc - optind > 1) {
			user("Overriding argv is not supported.");
			return EXIT_FAILURE;
		}

		fd = open(argv[optind], O_RDONLY);
		if (fd == -1) {
			crit("open %s", argv[optind]);
			return EXIT_FAILURE;
		}

		if (read_input(fd))
			return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}
