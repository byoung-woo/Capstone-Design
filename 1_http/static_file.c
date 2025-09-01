
#include "static_file.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>

void serve_static_file(int client_fd, const char *filename) {
    FILE *fp = fopen(filename, "rb");
    if (fp == NULL) {
        const char *response =
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html; charset=UTF-8\r\n"
            "Content-Length: 56\r\n"
            "\r\n"
            "<html><body><h1>404 - File Not Found</h1></body></html>";
        write(client_fd, response, strlen(response));
        return;
    }

    // 파일 크기 확인
    fseek(fp, 0, SEEK_END);
    long filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *file_buffer = malloc(filesize);
    if (file_buffer == NULL) {
        fclose(fp);
        return;
    }
    fread(file_buffer, 1, filesize, fp);
    fclose(fp);

    char header[256];
    snprintf(header, sizeof(header),
             "HTTP/1.1 200 OK\r\n"
             "Content-Type: text/html\r\n"
             "Content-Length: %ld\r\n"
             "\r\n", filesize);

    write(client_fd, header, strlen(header));
    write(client_fd, file_buffer, filesize);

    free(file_buffer);
}


