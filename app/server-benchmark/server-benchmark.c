
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <poll.h>
#include <sys/queue.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <errno.h>

#if !defined(TAILQ_FOREACH_SAFE)
#define	TAILQ_FOREACH_SAFE(var, head, field, next)		\
	for ((var) = ((head)->tqh_first);			\
		(var) && ((next) = ((var)->field.tqe_next), 1);	\
		(var) = (next))
#endif

#define OPTIONS_DEFAULT_REQUESTS	0
#define OPTIONS_DEFAULT_CONCURRENCY	0
#define OPTIONS_DEFAULT_TIMELIMIT	30000
#define OPTIONS_DEFAULT_TIMEOUT		30000
#define OPTIONS_DEFAULT_KEEPALIVE	0

#define OPTION_HELP			'h'
#define OPTION_REQUESTS			'n'
#define OPTION_CONCURRENCY		'c'
#define OPTION_TIMELIMIT		't'
#define OPTION_TIMEOUT			's'
#define OPTION_KEEPALIVE		'k'
static struct option longopts[] = {
	{ "help",		no_argument,		NULL,	OPTION_HELP		},
	{ "requests",		required_argument,	NULL,	OPTION_REQUESTS		},
	{ "concurrency",	required_argument,	NULL,	OPTION_CONCURRENCY	},
	{ "timelimit",		required_argument,	NULL,	OPTION_TIMELIMIT	},
	{ "timeout",		required_argument,	NULL,	OPTION_TIMEOUT		},
	{ "keepalive",		required_argument,	NULL,	OPTION_KEEPALIVE	},
	{ NULL,			0,			NULL,	0			},
};
static void usage (const char *pname)
{
	fprintf(stdout, "medusa http server benchmarking tool\n");
	fprintf(stdout, "\n");
	fprintf(stdout, "usage:\n");
	fprintf(stdout, "  %s [options] [http[s]://]hostname[:port]/path\n", pname);
	fprintf(stdout, "\n");
	fprintf(stdout, "options:\n");
	fprintf(stdout, "  -n, --requests   : number of requests to perform (default: %d)\n", OPTIONS_DEFAULT_REQUESTS);
	fprintf(stdout, "  -c, --concurrency: number of multiple requests to make at a time (default: %d)\n", OPTIONS_DEFAULT_CONCURRENCY);
	fprintf(stdout, "  -t, --timelimit  : milliseconds to max. to spend on benchmarking (default: %d)\n", OPTIONS_DEFAULT_TIMELIMIT);
	fprintf(stdout, "  -s, --timeout    : milliseconds to max. wait for each response (default: %d)\n", OPTIONS_DEFAULT_TIMEOUT);
	fprintf(stdout, "  -k, --keepalive  : use http keepalive feature (default: %d)\n", OPTIONS_DEFAULT_KEEPALIVE);
	fprintf(stdout, "  -h, --help       : this text\n");
}

struct options {
	long long requests;
	long long concurrency;
	long long timelimit;
	long long timeout;
	int keepalive;
	const char *url;
};

struct url {
	int refcount;
	char *uri;
	char *scheme;
	char *host;
	unsigned short port;
	char *path;
};

enum client_state {
	client_state_unknown,
	client_state_connecting,
	client_state_connected,
	client_state_disconnecting,
	client_state_disconnected
};

TAILQ_HEAD(clients, client);
struct client {
	TAILQ_ENTRY(client) clients;
	int fd;
	enum client_state state;
	long long requests;
};

#define debugf(fmt...) { \
	fprintf(stderr, "debug: "); \
	fprintf(stderr, fmt); \
	fprintf(stderr, " (%s %s:%d)\n", __FUNCTION__, __FILE__, __LINE__); \
}

#define infof(fmt...) { \
	fprintf(stderr, "info: "); \
	fprintf(stderr, fmt); \
	fprintf(stderr, " (%s %s:%d)\n", __FUNCTION__, __FILE__, __LINE__); \
}

#define errorf(fmt...) { \
	fprintf(stderr, "error: "); \
	fprintf(stderr, fmt); \
	fprintf(stderr, " (%s %s:%d)\n", __FUNCTION__, __FILE__, __LINE__); \
}

static __attribute__ ((unused)) const char * url_get_uri (struct url *url)
{
	if (url == NULL) {
		return NULL;
	}
	return url->uri;
}

static __attribute__ ((unused)) const char * url_get_scheme (struct url *url)
{
	if (url == NULL) {
		return NULL;
	}
	return url->scheme;
}

static __attribute__ ((unused)) const char * url_get_host (struct url *url)
{
	if (url == NULL) {
		return NULL;
	}
	return url->host;
}

static __attribute__ ((unused)) int url_get_port (struct url *url)
{
	if (url == NULL) {
		return 0;
	}
	return url->port;
}

static __attribute__ ((unused)) const char * url_get_path (struct url *url)
{
	if (url == NULL) {
		return NULL;
	}
	return url->path;
}

static __attribute__ ((unused)) struct url * url_copy (struct url *url)
{
	if (url == NULL) {
		return NULL;
	}
	url->refcount += 1;
	return url;
}

static __attribute__ ((unused)) void url_destroy (struct url *url)
{
	if (url == NULL) {
		return;
	}
	if (--url->refcount > 0) {
		return;
	}
	if (url->uri != NULL) {
		free(url->uri);
	}
	if (url->scheme != NULL) {
		free(url->scheme);
	}
	if (url->host != NULL) {
		free(url->host);
	}
	if (url->path != NULL) {
		free(url->path);
	}
	free(url);
}

static __attribute__ ((unused)) struct url * url_create (const char *uri)
{
	char *i;
	char *p;
	char *e;
	char *t;
	char *u;
	struct url *url;
	u = NULL;
	p = NULL;
	e = NULL;
	url = NULL;
	if (uri == NULL) {
		errorf("uri is invalid");
		goto bail;
	}
	url = malloc(sizeof(struct url));
	if (url == NULL) {
		errorf("can not allocate memory");
		goto bail;
	}
	memset(url, 0, sizeof(struct url));
	url->refcount = 1;
	u = strdup(uri);
	if (u == NULL) {
		errorf("can not allocate memory");
		goto bail;
	}
	if (u[0] == '<') {
		memmove(u, u + 1, strlen(u) - 1);
		t = strchr(u, '>');
		if (t != NULL) {
			*t = '\0';
		}
	}
	url->uri = strdup(u);
	if (url->uri == NULL) {
		errorf("can not allocate memory");
		goto bail;
	}
	i = strstr(u, "://");
	if (i != NULL) {
		url->scheme = strndup(u, i - u);
		i += 3;
	} else {
		i = u;
	}
	if (i != NULL) {
		p = strchr(i, ':');
		e = strchr(i, '/');
	}
	if (p == NULL && e == NULL) {
		url->port = 0;
		url->host = strdup(i);
	} else if (p != NULL && e == NULL) {
		url->port = atoi(p + 1);
		url->host = strndup(i, p - i);
	} else if (p == NULL || e < p) {
		url->port = 0;
		if (e == NULL) {
			url->host = strdup(i);
		} else {
			*e = '\0';
			url->host = strndup(i, e - i);
		}
	} else {
		if (e != NULL) {
			*e = '\0';
		}
		url->port = atoi(p + 1);
		url->host = strndup(i, p - i);
	}
	if (e != NULL) {
		do {
			e++;
		} while (*e == '/');
		url->path = strdup(e);
	}
	if (url->port == 0 &&
	    url->scheme != NULL) {
		if (strcmp(url->scheme, "http") == 0) {
			url->port = 80;
		}
	}
	free(u);
	return url;
bail:	if (url != NULL) {
		url_destroy(url);
	}
	if (u != NULL) {
		free(u);
	}
	return NULL;
}

static __attribute__ ((unused)) int client_set_requests (struct client *client, long long requests)
{
	if (client == NULL) {
		return -1;
	}
	client->requests = requests;
	return 0;
}

static __attribute__ ((unused)) int client_get_fd_error (struct client *client)
{
	int rc;
	int error;
	socklen_t len;
	len = sizeof(error);
	if (client == NULL) {
		return -EINVAL;
	}
	rc = getsockopt(client->fd, SOL_SOCKET, SO_ERROR, &error, &len);
	if (rc != 0) {
		return -EINVAL;
	}
	if (error == 0) {
		return 0;
	}
	return -error;
}

static __attribute__ ((unused)) int client_get_fd (struct client *client)
{
	if (client == NULL) {
		return -1;
	}
	return client->fd;
}

static __attribute__ ((unused)) enum client_state client_get_state (struct client *client)
{
	if (client == NULL) {
		return client_state_unknown;
	}
	return client->state;
}

static __attribute__ ((unused)) int client_set_state (struct client *client, enum client_state state)
{
	if (client == NULL) {
		return -1;
	}
	client->state = state;
	return 0;
}

static __attribute__ ((unused)) int client_connect (struct client *client, const char *address, int port)
{
	int rc;
	int opt;
	int flags;
	struct addrinfo hints;
	struct addrinfo *result;
	struct addrinfo *res;
	if (client == NULL) {
		errorf("client is invalid");
		goto bail;
	}
	if (address == NULL) {
		errorf("address is invalid");
		goto bail;
	}
	if (port <= 0 ||
	    port >= 0xffff) {
		errorf("port is invalid");
		goto bail;
	}
	if (client->fd >= 0) {
		shutdown(client->fd, SHUT_RDWR);
		close(client->fd);
		client->fd = -1;
	}
	client->fd = socket(AF_INET, SOCK_STREAM, 0);
	if (client->fd < 0) {
		errorf("can not open socket");
		goto bail;
	}
	opt = 1;
	rc = setsockopt(client->fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	if (rc < 0) {
		errorf("setsockopt reuseaddr failed");
		goto bail;
	}
	flags = fcntl(client->fd, F_GETFL, 0);
	if (flags < 0) {
		errorf("can not get flags");
		goto bail;
	}
	flags = flags | O_NONBLOCK;
	rc = fcntl(client->fd, F_SETFL, flags);
	if (rc != 0) {
		errorf("can not set flags");
		goto bail;
	}
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	rc = getaddrinfo(address, NULL, &hints, &result);
	if (rc != 0) {
		errorf("getaddrinfo failed for: %s", address);
		goto bail;
	}
	for (res = result; res; res = res->ai_next) {
		char str[INET_ADDRSTRLEN];
		struct sockaddr_in *sockaddr_in;
		if (res->ai_family != AF_INET) {
			continue;
		}
		inet_ntop(AF_INET, &(((struct sockaddr_in *) res->ai_addr)->sin_addr), str, sizeof(str));
		sockaddr_in = (struct sockaddr_in *) res->ai_addr;
		sockaddr_in->sin_port = htons(port);
		rc = connect(client->fd, res->ai_addr, res->ai_addrlen);
		if (rc != 0) {
			if (errno != EINPROGRESS) {
				continue;
			} else {
				rc = -errno;
			}
		}
		break;
	}
	freeaddrinfo(result);

	return 0;
bail:	if (client != NULL) {
		if (client->fd >= 0) {
			shutdown(client->fd, SHUT_RDWR);
			close(client->fd);
			client->fd = -1;
		}
	}
	if (result != NULL) {
		freeaddrinfo(result);
	}
	return -1;
}

static __attribute__ ((unused)) void client_destroy (struct client *client)
{
	if (client == NULL) {
		return;
	}
	if (client->fd >= 0) {
		shutdown(client->fd, SHUT_RDWR);
		close(client->fd);
	}
	free(client);
}

static __attribute__ ((unused)) struct client * client_create (void)
{
	struct client *client;
	client = malloc(sizeof(struct client));
	if (client == NULL) {
		errorf("can not allocate memory");
		goto bail;
	}
	memset(client, 0, sizeof(struct client));
	client->fd = -1;
	client->state = client_state_disconnected;
	return client;
bail:	if (client != NULL) {
		client_destroy(client);
	}
	return NULL;
}

int main (int argc, char *argv[])
{
	int c;
	int rc;
	int ret;

	struct options options;
	struct clients clients;

	long long i;
	struct url *url;
	struct client *client;
	struct client *nclient;
	long long npollfds;
	struct pollfd *pollfds;

	ret = 0;

	memset(&options, 0, sizeof(struct options));
	options.requests = OPTIONS_DEFAULT_REQUESTS;
	options.concurrency = OPTIONS_DEFAULT_CONCURRENCY;
	options.timelimit = OPTIONS_DEFAULT_TIMELIMIT;
	options.timeout = OPTIONS_DEFAULT_TIMEOUT;
	options.keepalive = OPTIONS_DEFAULT_KEEPALIVE;
	options.url = NULL;

	url = NULL;
	pollfds = NULL;
	TAILQ_INIT(&clients);

	while ((c = getopt_long(argc, argv, "hn:c:t:s:k:", longopts, NULL)) != -1) {
		switch (c) {
			case OPTION_HELP:
				usage(argv[0]);
				goto out;
			case OPTION_REQUESTS:
				options.requests = atoll(optarg);
				break;
			case OPTION_CONCURRENCY:
				options.concurrency = atoll(optarg);
				break;
			case OPTION_TIMELIMIT:
				options.timelimit = atoll(optarg);
				break;
			case OPTION_TIMEOUT:
				options.timeout = atoll(optarg);
				break;
			case OPTION_KEEPALIVE:
				options.keepalive = !!atoi(optarg);
				break;
			default:
				fprintf(stderr, "invalid option: %s\n", argv[optind - 1]);
				goto bail;
		}
	}

	if (optind + 1 != argc) {
		fprintf(stderr, "url parameter is missing\n");
		goto bail;
	}
	options.url = argv[optind++];


	fprintf(stdout, "medusa server benchmark\n");
	fprintf(stdout, "options\n");
	fprintf(stdout, "  requests   : %lld\n", options.requests);
	fprintf(stdout, "  concurrency: %lld\n", options.concurrency);
	fprintf(stdout, "  timelimit  : %lld\n", options.timelimit);
	fprintf(stdout, "  timeout    : %lld\n", options.timeout);
	fprintf(stdout, "  keepalive  : %d\n", options.keepalive);
	fprintf(stdout, "  url        : %s\n", options.url);

	url = url_create(options.url);
	if (url == NULL) {
		errorf("url is invalid");
		goto bail;
	}
	for (i = 0; i < options.concurrency; i++) {
		client = client_create();
		if (client == NULL) {
			errorf("can not create client");
			goto bail;
		}
		client_set_requests(client, options.requests);
		TAILQ_INSERT_TAIL(&clients, client, clients);
	}

	pollfds = malloc(sizeof(struct pollfd) * options.concurrency);
	if (pollfds == NULL) {
		errorf("can not allocate memory");
		goto bail;
	}
	memset(pollfds, 0, sizeof(struct pollfd) * options.concurrency);

	while (1) {
		TAILQ_FOREACH(client, &clients, clients) {
			if (client_get_state(client) == client_state_disconnected) {
				rc = client_connect(client, url_get_host(url), url_get_port(url));
				if (rc != 0) {
					errorf("can not connect client: %p to %s:%d", client, url_get_host(url), url_get_port(url));
					client_set_state(client, client_state_disconnected);
					goto bail;
				}
				client_set_state(client, client_state_connecting);
			}
		}
		npollfds = 0;
		TAILQ_FOREACH(client, &clients, clients) {
			if (client_get_state(client) == client_state_connecting) {
				pollfds[npollfds].fd = client_get_fd(client);
				pollfds[npollfds].events = POLLOUT;
				pollfds[npollfds].revents = 0;
				npollfds += 1;
			} else 	if (client_get_state(client) == client_state_connected) {
				errorf("not implemented yet");
				goto bail;
			}
		}
		rc = poll(pollfds, npollfds, 100);
		if (rc < 0) {
			errorf("poll failed with: %d", rc);
			goto bail;
		}
		if (rc == 0) {
			continue;
		}
		for (i = 0; i < npollfds; i++) {
			if (pollfds[i].revents == 0) {
				continue;
			}
			TAILQ_FOREACH(client, &clients, clients) {
				if (client_get_fd(client) == pollfds[i].fd) {
					break;
				}
			}
			if (client == NULL) {
				errorf("can not find client for fd: %d", pollfds[i].fd);
				goto bail;
			}
			if (pollfds[i].revents & POLLIN) {
				errorf("not implemented yet");
				goto bail;
			} else if (pollfds[i].revents & POLLOUT) {
				if (client_get_state(client) == client_state_connecting) {
					rc = client_get_fd_error(client);
					if (rc == 0) {
						client_set_state(client, client_state_connected);
					} else {
						errorf("client: %p failed to connect: %d", client, rc);
						goto bail;
					}
				} else {
					errorf("client: %p, state: %d", client, client_get_state(client));
					errorf("not implemented yet");
					goto bail;
				}
			} else if (pollfds[i].revents != 0) {
				errorf("not implemented yet");
				goto bail;
			}
		}
	}

out:	TAILQ_FOREACH_SAFE(client, &clients, clients, nclient) {
		TAILQ_REMOVE(&clients, client, clients);
		client_destroy(client);
	}
	if (url != NULL) {
		url_destroy(url);
	}
	if (pollfds != NULL) {
		free(pollfds);
	}
	return ret;
bail:	ret = -1;
	goto out;
}
