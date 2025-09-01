// logger.h
#ifndef LOGGER_H
#define LOGGER_H

void init_logger();
void log_error(const char* message);
void log_request(int client_socket, const char* request_buffer, int bytes_read);
void cleanup_logger();

#endif