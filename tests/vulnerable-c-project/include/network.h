#ifndef NETWORK_H
#define NETWORK_H

#include <time.h>
#include <stddef.h>

// Function declarations
int process_network_packet(char *packet_data, size_t data_len);
void parse_http_request(char *request);
void log_network_event(char *client_ip, char *event_msg);
char* allocate_receive_buffer(unsigned int packet_count, unsigned int packet_size);
int validate_hostname(const char *hostname);
void parse_url(const char *url, char *host, char *path, int *port);
void parse_cookies(const char *cookie_header);
void handle_client_connection(int client_socket);
int add_connection_to_pool(int socket_fd);
int setup_server(int port);

#endif // NETWORK_H