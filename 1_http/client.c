#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define PORT 8080
#define BUFFER_SIZE 1024

int main() {
    int sock;
    struct sockaddr_in server_addr;
    char request[] = "GET / HTTP/1.1\r\nHost: <서버_IP>\r\n\r\n";
    char buffer[BUFFER_SIZE];

    // 1. 소켓 생성 (TCP 소켓)
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("소켓 생성 실패");
        exit(EXIT_FAILURE);
    }
    
    // 2. 서버 주소 설정
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    // 아래의 <서버_IP>를 실제 서버의 IP 주소로 변경해야 함
    if (inet_pton(AF_INET, "192.168.1.100", &server_addr.sin_addr) <= 0) {
        perror("유효하지 않은 주소 또는 주소 변환 실패");
        exit(EXIT_FAILURE);
    }
    
    // 3. 서버에 연결
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("서버 연결 실패");
        exit(EXIT_FAILURE);
    }
    
    // 4. HTTP GET 요청 전송
    send(sock, request, strlen(request), 0);
    printf("HTTP 요청 전송됨:\n%s\n", request);
    
    // 5. 서버 응답 읽기 및 출력
    memset(buffer, 0, BUFFER_SIZE);
    read(sock, buffer, BUFFER_SIZE - 1);
    printf("서버 응답:\n%s\n", buffer);
    
    // 6. 소켓 닫기
    close(sock);
    return 0;
}
