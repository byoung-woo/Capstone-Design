
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "logger.h"
#include "path_response.h"

#define PORT 8080
#define BUFFER_SIZE 4096

int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);
    char buffer[BUFFER_SIZE];

    // 소켓 생성
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("소켓 생성 실패");
        exit(EXIT_FAILURE);
    }

    // 소켓 옵션 설정 (주소 재사용)
    int opt = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt 실패");
        exit(EXIT_FAILURE);
    }

    // 서버 주소 설정
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // 주소 바인딩
    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("바인드 실패");
        exit(EXIT_FAILURE);
    }

    // 리스닝 시작
    if (listen(server_fd, 10) < 0) {
        perror("리스닝 실패");
        exit(EXIT_FAILURE);
    }

    printf("웹서버가 포트 %d에서 실행 중...\n", PORT);

    while (1) {
        client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);
        if (client_fd < 0) {
            perror("클라이언트 연결 수락 실패");
            continue;
        }

        // 클라이언트 IP 주소 문자열로 변환
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);

        // 요청 메시지 읽기
        memset(buffer, 0, BUFFER_SIZE);
        read(client_fd, buffer, BUFFER_SIZE - 1);

        // 요청 로그 출력
        log_request(client_ip, buffer);

        // 요청 경로에 따른 응답 처리
        handle_request_path(client_fd, buffer);

        close(client_fd);
    }

    close(server_fd);
    return 0;
}


