
#ifndef DNSBENCH_H
#define DNSBENCH_H

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* --------------------------------------------------
 * Version and defaults
 * -------------------------------------------------- */

#define DNSBENCH_VERSION "0.1.0"

#define DNSBENCH_DEFAULT_ITERATIONS 3
#define DNSBENCH_DEFAULT_TIMEOUT 2
#define DNSBENCH_DEFAULT_PORT 53

#define DNSBENCH_MAX_TIMEOUT 3600
#define DNSBENCH_MAX_ITERATIONS 3600

#define DNSBENCH_IP_SIZE INET6_ADDRSTRLEN
#define DNSBENCH_DOMAIN_SIZE 256

/* --------------------------------------------------
 * Enumerations
 * -------------------------------------------------- */

typedef enum { DNS_TYPE_A = 1, DNS_TYPE_AAAA = 28 } DNSRecordType;

typedef enum {
  DNS_STATUS_SUCCESS = 0,
  DNS_STATUS_TIMEOUT,
  DNS_STATUS_NETWORK_ERROR,
  DNS_STATUS_DNS_ERROR,
  DNS_STATUS_NO_RECORD,
  DNS_STATUS_INVALID_RESPONSE,
  DNS_STATUS_INTERNAL_ERROR
} DNSStatus;

typedef enum {
  DNS_ADDRESS_IPV4 = AF_INET,
  DNS_ADDRESS_IPV6 = AF_INET6
} DNSAddressFamily;

/* --------------------------------------------------
 * Dynamic string list
 * -------------------------------------------------- */

typedef struct {
  char **items;
  size_t count;
  size_t capacity;
} StringList;

/* --------------------------------------------------
 * DNS server
 * -------------------------------------------------- */

typedef struct {
  char address[DNSBENCH_IP_SIZE];

  DNSAddressFamily family;

  uint16_t port;

  bool enabled;
} DNSServer;

/* --------------------------------------------------
 * DNS query result
 * -------------------------------------------------- */

typedef struct {
  bool success;

  DNSStatus status;

  char ip[DNSBENCH_IP_SIZE];

  double elapsed_ms;

  DNSRecordType record_type;
} DNSResult;

/* --------------------------------------------------
 * Latency statistics
 * -------------------------------------------------- */

typedef struct {
  double min;
  double max;
  double average;

  double median;

  double p95;
  double p99;
} LatencyStats;

/* --------------------------------------------------
 * DNS server statistics
 * -------------------------------------------------- */

typedef struct {
  char server[DNSBENCH_IP_SIZE];

  uint64_t total_queries;
  uint64_t successful_queries;
  uint64_t failed_queries;
  uint64_t timeout_queries;

  double total_latency;

  double success_rate;

  LatencyStats latency;

  /*
   * Stores successful query latencies.
   * Used for median, P95 and P99 calculations.
   */
  double *latencies;

  size_t latency_count;
  size_t latency_capacity;
  double min_latency;
  double max_latency;
  double avg_latency;

} DNSStats;

/* --------------------------------------------------
 * Benchmark configuration
 * -------------------------------------------------- */

typedef struct {
  StringList servers;
  StringList domains;

  int iterations;
  int timeout;

  uint16_t port;

  bool verbose;
  bool randomize;
  bool ipv4;
  bool ipv6;

  bool csv_enabled;

  const char *server_file;
  const char *domain_file;
  const char *csv_file;

} DNSBenchConfig;

/* --------------------------------------------------
 * Benchmark context
 * -------------------------------------------------- */

typedef struct {
  DNSBenchConfig config;

  DNSStats *stats;

  size_t server_count;

  double start_time;
  double end_time;

} DNSBench;

/* --------------------------------------------------
 * Utility functions
 * -------------------------------------------------- */

double dnsbench_get_time(void);

char *dnsbench_trim(char *str);

void dnsbench_list_free(StringList *list);

int dnsbench_list_add(StringList *list, const char *value);

int dnsbench_load_file(StringList *list, const char *path);

int dnsbench_load_defaults(StringList *list, const char **values, size_t count);

/* --------------------------------------------------
 * Validation
 * -------------------------------------------------- */

int dnsbench_validate_server(const char *address);

int dnsbench_validate_domain(const char *domain);

int dnsbench_validate_config(const DNSBenchConfig *config);

/* --------------------------------------------------
 * Configuration
 * -------------------------------------------------- */

void dnsbench_config_init(DNSBenchConfig *config);

void dnsbench_config_free(DNSBenchConfig *config);

int dnsbench_parse_args(int argc, char **argv, DNSBenchConfig *config);

void dnsbench_print_help(const char *program);

/* --------------------------------------------------
 * DNS resolution
 * -------------------------------------------------- */

DNSResult dnsbench_resolve(const char *server, uint16_t port,
                           const char *domain, DNSRecordType record_type,
                           int timeout);

/* --------------------------------------------------
 * Randomization
 * -------------------------------------------------- */

void dnsbench_shuffle_domains(StringList *domains);

/* --------------------------------------------------
 * Statistics
 * -------------------------------------------------- */

int dnsbench_add_latency(DNSStats *stats, double latency);

void dnsbench_calculate_statistics(DNSStats *stats);

double dnsbench_percentile(const double *values, size_t count,
                           double percentile);

int dnsbench_compare_stats(const void *a, const void *b);

void dnsbench_stats_free(DNSStats *stats);

/* --------------------------------------------------
 * Benchmark engine
 * -------------------------------------------------- */

int dnsbench_run(DNSBench *bench);

int dnsbench_benchmark_server(DNSStats *stats, const char *server,
                              const DNSBenchConfig *config);

/* --------------------------------------------------
 * Output
 * -------------------------------------------------- */

void dnsbench_print_results(DNSStats *stats, size_t count);

void dnsbench_print_verbose_result(const char *domain, const DNSResult *result);

int dnsbench_export_csv(const DNSStats *stats, size_t count,
                        const char *filename);

/* --------------------------------------------------
 * Error handling
 * -------------------------------------------------- */

const char *dnsbench_status_string(DNSStatus status);

/* --------------------------------------------------
 * Cleanup
 * -------------------------------------------------- */

void dnsbench_cleanup(DNSBench *bench);

#endif /* DNSBENCH_H */
