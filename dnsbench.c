
#define _POSIX_C_SOURCE 200809L

#include "dnsbench.h"

#include <arpa/nameser.h>

#include <errno.h>
#include <fcntl.h>
#include <float.h>
#include <getopt.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

/* ==================================================
 * Default configuration
 * ================================================== */

static const char *default_servers[] = {
    "8.8.8.8",      "8.8.4.4",         "1.1.1.1",        "1.0.0.1",
    "9.9.9.9",      "149.112.112.112", "208.67.222.222", "208.67.220.220",
    "94.140.14.14", "94.140.15.15"};

static const char *default_domains[] = {
    "google.com",  "cloudflare.com",    "microsoft.com",
    "github.com",  "youtube.com",       "wikipedia.org",
    "reddit.com",  "amazon.com",        "mozilla.org",
    "openai.com",  "stackoverflow.com", "spotify.com",
    "netflix.com", "duckduckgo.com",    "bbc.com"};

/* ==================================================
 * Internal helpers
 * ================================================== */

static uint16_t next_dns_id(void) {
  static uint16_t id = 0;

  if (id == 0) {
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());
    id = (uint16_t)(rand() & 0xffff);
  }

  return ++id;
}

static int wait_socket(int fd, short events, double deadline) {
  for (;;) {
    double remaining = deadline - dnsbench_get_time();

    if (remaining <= 0)
      return 0;

    int timeout_ms = (int)(remaining * 1000.0);

    if (timeout_ms < 1)
      timeout_ms = 1;

    struct pollfd pfd = {.fd = fd, .events = events};

    int rc = poll(&pfd, 1, timeout_ms);

    if (rc < 0 && errno == EINTR)
      continue;

    if (rc <= 0)
      return rc;

    if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
      return -1;

    if (pfd.revents & events)
      return 1;
  }
}

static int encode_domain(const char *domain, unsigned char *buffer,
                         size_t capacity) {
  size_t pos = 0;
  const char *label = domain;

  while (*label) {
    const char *dot = strchr(label, '.');

    size_t length = dot ? (size_t)(dot - label) : strlen(label);

    if (length == 0 || length > 63)
      return -1;

    if (pos + length + 2 > capacity)
      return -1;

    buffer[pos++] = (unsigned char)length;

    memcpy(buffer + pos, label, length);
    pos += length;

    if (!dot)
      break;

    label = dot + 1;

    if (!*label)
      break;
  }

  if (pos + 1 > capacity)
    return -1;

  buffer[pos++] = 0;

  return (int)pos;
}

static int build_dns_query(const char *domain, DNSRecordType type,
                           unsigned char *packet, size_t capacity,
                           uint16_t *query_id) {
  if (capacity < 12)
    return -1;

  memset(packet, 0, capacity);

  *query_id = next_dns_id();

  packet[0] = (unsigned char)(*query_id >> 8);
  packet[1] = (unsigned char)(*query_id & 0xff);

  /* Standard query, recursion desired. */
  packet[2] = 0x01;
  packet[3] = 0x00;

  /* One question. */
  packet[4] = 0x00;
  packet[5] = 0x01;

  int encoded = encode_domain(domain, packet + 12, capacity - 12);

  if (encoded < 0)
    return -1;

  size_t pos = 12 + (size_t)encoded;

  if (pos + 4 > capacity)
    return -1;

  uint16_t qtype = (uint16_t)type;

  packet[pos++] = (unsigned char)(qtype >> 8);
  packet[pos++] = (unsigned char)(qtype & 0xff);

  /* Class IN. */
  packet[pos++] = 0x00;
  packet[pos++] = 0x01;

  return (int)pos;
}

static DNSStatus parse_dns_response(const unsigned char *packet, size_t length,
                                    uint16_t expected_id, DNSRecordType type,
                                    char *ip, size_t ip_size) {
  if (length < 12)
    return DNS_STATUS_INVALID_RESPONSE;

  uint16_t received_id = ((uint16_t)packet[0] << 8) | packet[1];

  if (received_id != expected_id)
    return DNS_STATUS_INVALID_RESPONSE;

  if (!(packet[2] & 0x80))
    return DNS_STATUS_INVALID_RESPONSE;

  ns_msg message;

  if (ns_initparse(packet, (int)length, &message) < 0)
    return DNS_STATUS_INVALID_RESPONSE;

  int rcode = ns_msg_getflag(message, ns_f_rcode);

  if (rcode != ns_r_noerror)
    return DNS_STATUS_DNS_ERROR;

  int count = ns_msg_count(message, ns_s_an);

  for (int i = 0; i < count; i++) {
    ns_rr record;

    if (ns_parserr(&message, ns_s_an, i, &record) < 0)
      continue;

    if (ns_rr_type(record) != (uint16_t)type)
      continue;

    if (ns_rr_class(record) != ns_c_in)
      continue;

    const unsigned char *data = ns_rr_rdata(record);

    if (type == DNS_TYPE_A && ns_rr_rdlen(record) == 4) {
      if (!inet_ntop(AF_INET, data, ip, ip_size))
        return DNS_STATUS_INTERNAL_ERROR;

      return DNS_STATUS_SUCCESS;
    }

    if (type == DNS_TYPE_AAAA && ns_rr_rdlen(record) == 16) {
      if (!inet_ntop(AF_INET6, data, ip, ip_size))
        return DNS_STATUS_INTERNAL_ERROR;

      return DNS_STATUS_SUCCESS;
    }
  }

  return DNS_STATUS_NO_RECORD;
}

/* ==================================================
 * TCP fallback
 * ================================================== */

static DNSStatus dns_tcp_query(int family, const struct sockaddr *address,
                               socklen_t address_length,
                               const unsigned char *query, size_t query_length,
                               uint16_t query_id, DNSRecordType type,
                               int timeout, char *ip) {
  int fd = socket(family, SOCK_STREAM, 0);

  if (fd < 0)
    return DNS_STATUS_NETWORK_ERROR;

  int flags = fcntl(fd, F_GETFL, 0);

  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    close(fd);
    return DNS_STATUS_NETWORK_ERROR;
  }

  double deadline = dnsbench_get_time() + timeout;

  int rc = connect(fd, address, address_length);

  if (rc < 0 && errno != EINPROGRESS) {
    close(fd);
    return DNS_STATUS_NETWORK_ERROR;
  }

  if (rc < 0) {
    rc = wait_socket(fd, POLLOUT, deadline);

    if (rc == 0) {
      close(fd);
      return DNS_STATUS_TIMEOUT;
    }

    if (rc < 0) {
      close(fd);
      return DNS_STATUS_NETWORK_ERROR;
    }

    int error = 0;
    socklen_t error_length = sizeof(error);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) < 0 ||
        error != 0) {
      close(fd);
      return DNS_STATUS_NETWORK_ERROR;
    }
  }

  unsigned char buffer[65537];

  buffer[0] = (unsigned char)(query_length >> 8);
  buffer[1] = (unsigned char)(query_length & 0xff);

  memcpy(buffer + 2, query, query_length);

  size_t total = query_length + 2;
  size_t sent = 0;

  while (sent < total) {
    rc = wait_socket(fd, POLLOUT, deadline);

    if (rc <= 0) {
      close(fd);
      return rc == 0 ? DNS_STATUS_TIMEOUT : DNS_STATUS_NETWORK_ERROR;
    }

    ssize_t n = send(fd, buffer + sent, total - sent, 0);

    if (n < 0) {
      if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
        continue;

      close(fd);
      return DNS_STATUS_NETWORK_ERROR;
    }

    sent += (size_t)n;
  }

  size_t received = 0;

  while (received < 2) {
    rc = wait_socket(fd, POLLIN, deadline);

    if (rc <= 0) {
      close(fd);
      return rc == 0 ? DNS_STATUS_TIMEOUT : DNS_STATUS_NETWORK_ERROR;
    }

    ssize_t n = recv(fd, buffer + received, 2 - received, 0);

    if (n <= 0) {
      if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
        continue;

      close(fd);
      return DNS_STATUS_NETWORK_ERROR;
    }

    received += (size_t)n;
  }

  size_t response_length = ((size_t)buffer[0] << 8) | buffer[1];

  if (response_length < 12 || response_length > sizeof(buffer) - 2) {
    close(fd);
    return DNS_STATUS_INVALID_RESPONSE;
  }

  received = 0;

  while (received < response_length) {
    rc = wait_socket(fd, POLLIN, deadline);

    if (rc <= 0) {
      close(fd);
      return rc == 0 ? DNS_STATUS_TIMEOUT : DNS_STATUS_NETWORK_ERROR;
    }

    ssize_t n = recv(fd, buffer + 2 + received, response_length - received, 0);

    if (n <= 0) {
      if (n < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK))
        continue;

      close(fd);
      return DNS_STATUS_NETWORK_ERROR;
    }

    received += (size_t)n;
  }

  close(fd);

  return parse_dns_response(buffer + 2, response_length, query_id, type, ip,
                            DNSBENCH_IP_SIZE);
}

/* ==================================================
 * Time and string utilities
 * ================================================== */

double dnsbench_get_time(void) {
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return 0.0;

  return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

char *dnsbench_trim(char *str) {
  while (*str && (unsigned char)*str <= ' ')
    str++;

  char *end = str + strlen(str);

  while (end > str && (unsigned char)end[-1] <= ' ')
    end--;

  *end = '\0';

  return str;
}

/* ==================================================
 * String list
 * ================================================== */

void dnsbench_list_free(StringList *list) {
  if (!list)
    return;

  for (size_t i = 0; i < list->count; i++)
    free(list->items[i]);

  free(list->items);

  memset(list, 0, sizeof(*list));
}

int dnsbench_list_add(StringList *list, const char *value) {
  if (list->count == list->capacity) {
    size_t capacity = list->capacity ? list->capacity * 2 : 16;

    if (capacity < list->capacity || capacity > SIZE_MAX / sizeof(char *))
      return -1;

    char **items = realloc(list->items, capacity * sizeof(char *));

    if (!items)
      return -1;

    list->items = items;
    list->capacity = capacity;
  }

  char *copy = strdup(value);

  if (!copy)
    return -1;

  list->items[list->count++] = copy;

  return 0;
}

int dnsbench_load_file(StringList *list, const char *path) {
  FILE *file = fopen(path, "r");

  if (!file) {
    fprintf(stderr, "Cannot open %s: %s\n", path, strerror(errno));
    return -1;
  }

  char *line = NULL;
  size_t capacity = 0;
  ssize_t length;
  size_t loaded = 0;

  while ((length = getline(&line, &capacity, file)) != -1) {
    (void)length;

    char *value = dnsbench_trim(line);

    if (*value == '\0' || *value == '#')
      continue;

    char *comment = strchr(value, '#');

    if (comment) {
      *comment = '\0';
      value = dnsbench_trim(value);
    }

    if (!*value)
      continue;

    if (dnsbench_list_add(list, value) != 0) {
      fprintf(stderr, "Memory allocation failed\n");
      free(line);
      fclose(file);
      return -1;
    }

    loaded++;
  }

  int read_error = ferror(file);

  free(line);
  fclose(file);

  if (read_error) {
    fprintf(stderr, "Error reading %s\n", path);
    return -1;
  }

  if (loaded == 0) {
    fprintf(stderr, "No entries found in %s\n", path);
    return -1;
  }

  return 0;
}

int dnsbench_load_defaults(StringList *list, const char **values,
                           size_t count) {
  for (size_t i = 0; i < count; i++) {
    if (dnsbench_list_add(list, values[i]) != 0)
      return -1;
  }

  return 0;
}

/* ==================================================
 * Validation
 * ================================================== */

int dnsbench_validate_server(const char *address) {
  struct in_addr ipv4;
  struct in6_addr ipv6;

  return inet_pton(AF_INET, address, &ipv4) == 1 ||
         inet_pton(AF_INET6, address, &ipv6) == 1;
}

int dnsbench_validate_domain(const char *domain) {
  if (!domain || !*domain)
    return 0;

  size_t length = strlen(domain);

  if (length > DNSBENCH_DOMAIN_SIZE - 1)
    return 0;

  if (domain[0] == '.' || domain[length - 1] == '.')
    return 0;

  size_t label_length = 0;

  for (size_t i = 0; i < length; i++) {
    unsigned char c = (unsigned char)domain[i];

    if (c == '.') {
      if (label_length == 0 || label_length > 63)
        return 0;

      label_length = 0;
      continue;
    }

    if (!(isalnum(c) || c == '-'))
      return 0;

    if (label_length == 0 && c == '-')
      return 0;

    if (c == '-' && i + 1 < length && domain[i + 1] == '.')
      return 0;

    label_length++;
  }

  return label_length > 0 && label_length <= 63 && domain[length - 1] != '-';
}

int dnsbench_validate_config(const DNSBenchConfig *config) {
  if (!config->servers.count || !config->domains.count) {
    fprintf(stderr, "Server and domain lists cannot be empty.\n");
    return -1;
  }

  if (!config->ipv4 && !config->ipv6) {
    fprintf(stderr, "At least one record type must be enabled.\n");
    return -1;
  }

  for (size_t i = 0; i < config->servers.count; i++) {
    if (!dnsbench_validate_server(config->servers.items[i])) {
      fprintf(stderr, "Invalid DNS server: %s\n", config->servers.items[i]);
      return -1;
    }
  }

  for (size_t i = 0; i < config->domains.count; i++) {
    if (!dnsbench_validate_domain(config->domains.items[i])) {
      fprintf(stderr, "Invalid domain: %s\n", config->domains.items[i]);
      return -1;
    }
  }

  return 0;
}

/* ==================================================
 * Configuration and CLI
 * ================================================== */

void dnsbench_config_init(DNSBenchConfig *config) {
  memset(config, 0, sizeof(*config));

  config->iterations = DNSBENCH_DEFAULT_ITERATIONS;
  config->timeout = DNSBENCH_DEFAULT_TIMEOUT;
  config->port = DNSBENCH_DEFAULT_PORT;

  config->ipv4 = true;
  config->ipv6 = true;
}

void dnsbench_config_free(DNSBenchConfig *config) {
  dnsbench_list_free(&config->servers);
  dnsbench_list_free(&config->domains);
}

void dnsbench_print_help(const char *program) {
  printf("DNSBench %s\n\n"
         "Usage: %s [OPTIONS]\n\n"
         "Options:\n"
         "  -s, --servers FILE       DNS server list\n"
         "  -d, --domains FILE       Domain list\n"
         "  -n, --iterations NUM     Number of iterations\n"
         "  -t, --timeout SEC        Per-query timeout\n"
         "  -p, --port PORT          DNS server port\n"
         "  -4, --ipv4               Enable A queries only\n"
         "  -6, --ipv6               Enable AAAA queries only\n"
         "  -r, --random             Randomize domain order\n"
         "  -o, --output FILE        Export results to CSV\n"
         "  -v, --verbose            Verbose output\n"
         "  -h, --help               Show help\n"
         "  -V, --version            Show version\n\n"
         "Examples:\n"
         "  %s\n"
         "  %s -n 10 -t 3\n"
         "  %s -s dns.txt -d domains.txt\n"
         "  %s -4 -n 20 -o results.csv\n"
         "  %s -6 -r -v\n",
         DNSBENCH_VERSION, program, program, program, program, program,
         program);
}

static int parse_positive_int(const char *value, int *result) {
  char *end = NULL;

  errno = 0;

  long number = strtol(value, &end, 10);

  if (errno || end == value || *end != '\0' || number < 1 ||
      number > DNSBENCH_MAX_ITERATIONS)
    return -1;

  *result = (int)number;

  return 0;
}

int dnsbench_parse_args(int argc, char **argv, DNSBenchConfig *config) {
  static const struct option options[] = {
      {"servers", required_argument, NULL, 's'},
      {"domains", required_argument, NULL, 'd'},
      {"iterations", required_argument, NULL, 'n'},
      {"timeout", required_argument, NULL, 't'},
      {"port", required_argument, NULL, 'p'},
      {"ipv4", no_argument, NULL, '4'},
      {"ipv6", no_argument, NULL, '6'},
      {"random", no_argument, NULL, 'r'},
      {"output", required_argument, NULL, 'o'},
      {"verbose", no_argument, NULL, 'v'},
      {"help", no_argument, NULL, 'h'},
      {"version", no_argument, NULL, 'V'},
      {NULL, 0, NULL, 0}};

  int option;

  while ((option = getopt_long(argc, argv, "s:d:n:t:p:46ro:vhV", options,
                               NULL)) != -1) {

    switch (option) {
    case 's':
      config->server_file = optarg;
      break;

    case 'd':
      config->domain_file = optarg;
      break;

    case 'n':
      if (parse_positive_int(optarg, &config->iterations) != 0)
        return -1;
      break;

    case 't':
      if (parse_positive_int(optarg, &config->timeout) != 0)
        return -1;
      break;

    case 'p': {
      int port;

      if (parse_positive_int(optarg, &port) != 0 || port > 65535)
        return -1;

      config->port = (uint16_t)port;
      break;
    }

    case '4':
      config->ipv4 = true;
      config->ipv6 = false;
      break;

    case '6':
      config->ipv4 = false;
      config->ipv6 = true;
      break;

    case 'r':
      config->randomize = true;
      break;

    case 'o':
      config->csv_file = optarg;
      config->csv_enabled = true;
      break;

    case 'v':
      config->verbose = true;
      break;

    case 'h':
      dnsbench_print_help(argv[0]);
      exit(EXIT_SUCCESS);

    case 'V':
      printf("DNSBench %s\n", DNSBENCH_VERSION);
      exit(EXIT_SUCCESS);

    default:
      return -1;
    }
  }

  if (optind < argc) {
    fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
    return -1;
  }

  return 0;
}

/* ==================================================
 * DNS resolution
 * ================================================== */

DNSResult dnsbench_resolve(const char *server, uint16_t port,
                           const char *domain, DNSRecordType record_type,
                           int timeout) {
  DNSResult result = {0};

  result.status = DNS_STATUS_INTERNAL_ERROR;
  result.record_type = record_type;

  unsigned char query[512];
  unsigned char answer[65536];

  uint16_t query_id;

  int query_length =
      build_dns_query(domain, record_type, query, sizeof(query), &query_id);

  if (query_length < 0)
    return result;

  struct sockaddr_storage address;
  socklen_t address_length;
  int family;

  memset(&address, 0, sizeof(address));

  struct sockaddr_in *v4 = (struct sockaddr_in *)&address;

  struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&address;

  if (inet_pton(AF_INET, server, &v4->sin_addr) == 1) {
    family = AF_INET;
    v4->sin_family = AF_INET;
    v4->sin_port = htons(port);
    address_length = sizeof(*v4);
  } else if (inet_pton(AF_INET6, server, &v6->sin6_addr) == 1) {
    family = AF_INET6;
    v6->sin6_family = AF_INET6;
    v6->sin6_port = htons(port);
    address_length = sizeof(*v6);
  } else {
    result.status = DNS_STATUS_INTERNAL_ERROR;
    return result;
  }

  double start = dnsbench_get_time();
  double deadline = start + timeout;

  int fd = socket(family, SOCK_DGRAM, 0);

  if (fd < 0) {
    result.status = DNS_STATUS_NETWORK_ERROR;
    return result;
  }

  if (connect(fd, (struct sockaddr *)&address, address_length) < 0) {
    close(fd);
    result.status = DNS_STATUS_NETWORK_ERROR;
    return result;
  }

  ssize_t sent = send(fd, query, (size_t)query_length, 0);

  if (sent != query_length) {
    close(fd);
    result.status = DNS_STATUS_NETWORK_ERROR;
    return result;
  }

  int ready = wait_socket(fd, POLLIN, deadline);

  if (ready <= 0) {
    close(fd);

    result.status = ready == 0 ? DNS_STATUS_TIMEOUT : DNS_STATUS_NETWORK_ERROR;

    result.elapsed_ms = (dnsbench_get_time() - start) * 1000.0;

    return result;
  }

  ssize_t received = recv(fd, answer, sizeof(answer), 0);

  close(fd);

  if (received < 0) {
    result.status = DNS_STATUS_NETWORK_ERROR;
    result.elapsed_ms = (dnsbench_get_time() - start) * 1000.0;
    return result;
  }

  /* TCP fallback if the UDP response is truncated. */
  if (received >= 4 && (answer[2] & 0x02)) {
    result.status = dns_tcp_query(family, (struct sockaddr *)&address,
                                  address_length, query, (size_t)query_length,
                                  query_id, record_type, timeout, result.ip);
  } else {
    result.status =
        parse_dns_response(answer, (size_t)received, query_id, record_type,
                           result.ip, sizeof(result.ip));
  }

  result.elapsed_ms = (dnsbench_get_time() - start) * 1000.0;

  result.success = result.status == DNS_STATUS_SUCCESS;

  return result;
}

/* ==================================================
 * Randomization
 * ================================================== */

void dnsbench_shuffle_domains(StringList *domains) {
  if (domains->count < 2)
    return;

  for (size_t i = domains->count - 1; i > 0; i--) {
    size_t j = (size_t)rand() % (i + 1);

    char *temp = domains->items[i];
    domains->items[i] = domains->items[j];
    domains->items[j] = temp;
  }
}

/* ==================================================
 * Statistics
 * ================================================== */

int dnsbench_add_latency(DNSStats *stats, double latency) {
  if (stats->latency_count == stats->latency_capacity) {
    size_t capacity =
        stats->latency_capacity ? stats->latency_capacity * 2 : 32;

    if (capacity < stats->latency_capacity ||
        capacity > SIZE_MAX / sizeof(double))
      return -1;

    double *values = realloc(stats->latencies, capacity * sizeof(double));

    if (!values)
      return -1;

    stats->latencies = values;
    stats->latency_capacity = capacity;
  }

  stats->latencies[stats->latency_count++] = latency;

  return 0;
}

static int compare_double(const void *a, const void *b) {
  double x = *(const double *)a;
  double y = *(const double *)b;

  return (x > y) - (x < y);
}

double dnsbench_percentile(const double *values, size_t count,
                           double percentile) {
  if (!values || count == 0)
    return 0.0;

  if (percentile < 0.0)
    percentile = 0.0;

  if (percentile > 100.0)
    percentile = 100.0;

  double position = (percentile / 100.0) * (count - 1);

  size_t lower = (size_t)position;
  size_t upper = lower + 1;

  if (upper >= count)
    return values[count - 1];

  double fraction = position - lower;

  return values[lower] + fraction * (values[upper] - values[lower]);
}

void dnsbench_calculate_statistics(DNSStats *stats) {
  if (!stats->successful_queries)
    return;

  stats->avg_latency = stats->total_latency / (double)stats->successful_queries;

  qsort(stats->latencies, stats->latency_count, sizeof(double), compare_double);

  stats->latency.min = stats->latencies[0];

  stats->latency.max = stats->latencies[stats->latency_count - 1];

  stats->latency.average = stats->avg_latency;

  stats->latency.median =
      dnsbench_percentile(stats->latencies, stats->latency_count, 50.0);

  stats->latency.p95 =
      dnsbench_percentile(stats->latencies, stats->latency_count, 95.0);

  stats->latency.p99 =
      dnsbench_percentile(stats->latencies, stats->latency_count, 99.0);

  stats->min_latency = stats->latency.min;
  stats->max_latency = stats->latency.max;
}

int dnsbench_compare_stats(const void *a, const void *b) {
  const DNSStats *x = a;
  const DNSStats *y = b;

  if (x->success_rate > y->success_rate)
    return -1;

  if (x->success_rate < y->success_rate)
    return 1;

  if (x->avg_latency < y->avg_latency)
    return -1;

  if (x->avg_latency > y->avg_latency)
    return 1;

  return 0;
}

void dnsbench_stats_free(DNSStats *stats) {
  if (!stats)
    return;

  free(stats->latencies);

  stats->latencies = NULL;
  stats->latency_count = 0;
  stats->latency_capacity = 0;
}

/* ==================================================
 * Status messages
 * ================================================== */

const char *dnsbench_status_string(DNSStatus status) {
  switch (status) {
  case DNS_STATUS_SUCCESS:
    return "Success";

  case DNS_STATUS_TIMEOUT:
    return "Timeout";

  case DNS_STATUS_NETWORK_ERROR:
    return "Network error";

  case DNS_STATUS_DNS_ERROR:
    return "DNS error";

  case DNS_STATUS_NO_RECORD:
    return "No record";

  case DNS_STATUS_INVALID_RESPONSE:
    return "Invalid response";

  case DNS_STATUS_INTERNAL_ERROR:
    return "Internal error";

  default:
    return "Unknown";
  }
}

/* ==================================================
 * Verbose output
 * ================================================== */

void dnsbench_print_verbose_result(const char *domain,
                                   const DNSResult *result) {
  if (result->success) {
    printf("  [OK]   %-30s %-40s %.3f ms\n", domain, result->ip,
           result->elapsed_ms);
  } else {
    printf("  [FAIL] %-30s %-18s %.3f ms\n", domain,
           dnsbench_status_string(result->status), result->elapsed_ms);
  }
}

/* ==================================================
 * Benchmark engine
 * ================================================== */

int dnsbench_benchmark_server(DNSStats *stats, const char *server,
                              const DNSBenchConfig *config) {
  memset(stats, 0, sizeof(*stats));

  snprintf(stats->server, sizeof(stats->server), "%s", server);

  printf("\nBenchmarking %s\n", server);

  size_t type_count = (config->ipv4 ? 1u : 0u) + (config->ipv6 ? 1u : 0u);

  if (config->domains.count >
      UINT64_MAX / (uint64_t)config->iterations / type_count) {
    fprintf(stderr, "Too many benchmark queries.\n");
    return -1;
  }

  uint64_t total = (uint64_t)config->iterations *
                   (uint64_t)config->domains.count * (uint64_t)type_count;

  DNSRecordType types[2];
  size_t type_index = 0;

  if (config->ipv4)
    types[type_index++] = DNS_TYPE_A;

  if (config->ipv6)
    types[type_index++] = DNS_TYPE_AAAA;

  for (int iteration = 0; iteration < config->iterations; iteration++) {

    if (config->randomize)
      dnsbench_shuffle_domains((StringList *)&config->domains);

    for (size_t j = 0; j < config->domains.count; j++) {
      const char *domain = config->domains.items[j];

      for (size_t k = 0; k < type_count; k++) {
        DNSResult result = dnsbench_resolve(server, config->port, domain,
                                            types[k], config->timeout);

        stats->total_queries++;

        if (result.success) {
          stats->successful_queries++;
          stats->total_latency += result.elapsed_ms;

          if (dnsbench_add_latency(stats, result.elapsed_ms) != 0) {
            fprintf(stderr, "Could not store latency statistics.\n");
            return -1;
          }
        } else {
          stats->failed_queries++;

          if (result.status == DNS_STATUS_TIMEOUT)
            stats->timeout_queries++;
        }

        if (config->verbose) {
          dnsbench_print_verbose_result(domain, &result);
        } else {
          printf("\rProgress: %llu/%llu",
                 (unsigned long long)stats->total_queries,
                 (unsigned long long)total);

          fflush(stdout);
        }
      }
    }
  }

  if (stats->total_queries) {
    stats->success_rate = (double)stats->successful_queries /
                          (double)stats->total_queries * 100.0;
  }

  dnsbench_calculate_statistics(stats);

  if (!config->verbose)
    printf("\n");

  printf("Completed: %s | Success: %llu/%llu | Average: %.3f ms\n", server,
         (unsigned long long)stats->successful_queries,
         (unsigned long long)stats->total_queries, stats->avg_latency);

  return 0;
}

int dnsbench_run(DNSBench *bench) {
  bench->server_count = bench->config.servers.count;

  bench->stats = calloc(bench->server_count, sizeof(*bench->stats));

  if (!bench->stats) {
    fprintf(stderr, "Memory allocation failed\n");
    return -1;
  }

  bench->start_time = dnsbench_get_time();

  for (size_t i = 0; i < bench->server_count; i++) {
    if (dnsbench_benchmark_server(&bench->stats[i],
                                  bench->config.servers.items[i],
                                  &bench->config) != 0)
      return -1;
  }

  bench->end_time = dnsbench_get_time();

  return 0;
}

/* ==================================================
 * Results
 * ================================================== */

void dnsbench_print_results(DNSStats *stats, size_t count) {
  qsort(stats, count, sizeof(*stats), dnsbench_compare_stats);

  printf("\n");
  printf("====================================================================="
         "===================\n");
  printf("                                DNS BENCHMARK RESULTS\n");
  printf("====================================================================="
         "===================\n");

  printf("%-5s %-18s %-10s %-10s %-10s %-10s %-10s %-10s %-9s\n", "Rank",
         "DNS Server", "Avg", "Min", "Max", "Median", "P95", "Success%",
         "Timeouts");

  printf("---------------------------------------------------------------------"
         "-------------------\n");

  for (size_t i = 0; i < count; i++) {
    printf(
        "%-5zu %-18s %-10.3f %-10.3f %-10.3f %-10.3f %-10.3f %-10.1f %-9llu\n",
        i + 1, stats[i].server, stats[i].latency.average, stats[i].latency.min,
        stats[i].latency.max, stats[i].latency.median, stats[i].latency.p95,
        stats[i].success_rate, (unsigned long long)stats[i].timeout_queries);
  }

  printf("====================================================================="
         "===================\n");

  if (count && stats[0].successful_queries) {
    printf("Best candidate: %s\n", stats[0].server);
  } else {
    printf("No DNS server successfully resolved any domain.\n");
  }
}

/* ==================================================
 * CSV export
 * ================================================== */

int dnsbench_export_csv(const DNSStats *stats, size_t count,
                        const char *filename) {
  FILE *file = fopen(filename, "w");

  if (!file) {
    fprintf(stderr, "Cannot create %s: %s\n", filename, strerror(errno));
    return -1;
  }

  fprintf(file, "server,total,successful,failed,timeouts,"
                "success_rate,average_ms,min_ms,max_ms,"
                "median_ms,p95_ms,p99_ms\n");

  for (size_t i = 0; i < count; i++) {
    fprintf(file,
            "%s,%llu,%llu,%llu,%llu,%.2f,"
            "%.3f,%.3f,%.3f,%.3f,%.3f,%.3f\n",
            stats[i].server, (unsigned long long)stats[i].total_queries,
            (unsigned long long)stats[i].successful_queries,
            (unsigned long long)stats[i].failed_queries,
            (unsigned long long)stats[i].timeout_queries, stats[i].success_rate,
            stats[i].latency.average, stats[i].latency.min,
            stats[i].latency.max, stats[i].latency.median, stats[i].latency.p95,
            stats[i].latency.p99);
  }

  if (fclose(file) != 0) {
    fprintf(stderr, "Error writing CSV file.\n");
    return -1;
  }

  printf("CSV exported to %s\n", filename);

  return 0;
}

/* ==================================================
 * Cleanup
 * ================================================== */

void dnsbench_cleanup(DNSBench *bench) {
  if (!bench)
    return;

  if (bench->stats) {
    for (size_t i = 0; i < bench->server_count; i++)
      dnsbench_stats_free(&bench->stats[i]);

    free(bench->stats);
    bench->stats = NULL;
  }

  bench->server_count = 0;

  dnsbench_config_free(&bench->config);
}

/* ==================================================
 * Main
 * ================================================== */

int main(int argc, char **argv) {
  DNSBench bench = {0};

  dnsbench_config_init(&bench.config);

  if (dnsbench_parse_args(argc, argv, &bench.config) != 0) {
    fprintf(stderr, "Use --help for usage information.\n");
    dnsbench_cleanup(&bench);
    return EXIT_FAILURE;
  }

  if (bench.config.server_file) {
    if (dnsbench_load_file(&bench.config.servers, bench.config.server_file) !=
        0)
      goto error;
  } else {
    if (dnsbench_load_defaults(&bench.config.servers, default_servers,
                               sizeof(default_servers) /
                                   sizeof(default_servers[0])) != 0)
      goto error;
  }

  if (bench.config.domain_file) {
    if (dnsbench_load_file(&bench.config.domains, bench.config.domain_file) !=
        0)
      goto error;
  } else {
    if (dnsbench_load_defaults(&bench.config.domains, default_domains,
                               sizeof(default_domains) /
                                   sizeof(default_domains[0])) != 0)
      goto error;
  }

  if (dnsbench_validate_config(&bench.config) != 0)
    goto error;

  size_t type_count =
      (bench.config.ipv4 ? 1u : 0u) + (bench.config.ipv6 ? 1u : 0u);

  printf("DNSBench %s\n", DNSBENCH_VERSION);
  printf("----------------------------------------\n");
  printf("DNS servers : %zu\n", bench.config.servers.count);
  printf("Domains     : %zu\n", bench.config.domains.count);
  printf("Iterations  : %d\n", bench.config.iterations);
  printf("Timeout     : %d seconds\n", bench.config.timeout);
  printf("DNS port    : %u\n", bench.config.port);
  printf("Record types: %s%s\n", bench.config.ipv4 ? "A " : "",
         bench.config.ipv6 ? "AAAA" : "");

  printf("Total tests : %zu\n",
         bench.config.servers.count * bench.config.domains.count *
             (size_t)bench.config.iterations * type_count);

  if (dnsbench_run(&bench) != 0)
    goto error;

  dnsbench_print_results(bench.stats, bench.server_count);

  printf("Total benchmark time: %.2f seconds\n",
         bench.end_time - bench.start_time);

  if (bench.config.csv_enabled) {
    if (dnsbench_export_csv(bench.stats, bench.server_count,
                            bench.config.csv_file) != 0)
      goto error;
  }

  dnsbench_cleanup(&bench);

  return EXIT_SUCCESS;

error:
  dnsbench_cleanup(&bench);
  return EXIT_FAILURE;
}
