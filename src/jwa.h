#ifndef JOSECJWA_H_
#define JOSECJWA_H_


typedef enum
{
    INVALID,
    ES256,
    HS256,
    NONE,
    JWA_MAX
} jwa_t;

jwa_t
jwa2enum (const char *str);

#endif
