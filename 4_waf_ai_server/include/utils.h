#ifndef UTILS_H
#define UTILS_H
#include <stdlib.h> // size_t 사용을 위해

void url_decode(char *str);
char* get_form_value(const char* body, const char* key, char* output, size_t output_size);

#endif