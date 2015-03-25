/*
 * Simple example of parsing and printing JSON using jansson.
 *
 * SYNOPSIS:
 * $ examples/simple_parse
 * Type some JSON > [true, false, null, 1, 0.0, -0.0, "", {"name": "barney"}]
 * JSON Array of 8 elements:
 *   JSON True
 *   JSON False
 *   JSON Null
 *   JSON Integer: "1"
 *   JSON Real: 0.000000
 *   JSON Real: -0.000000
 *   JSON String: ""
 *   JSON Object of 1 pair:
 *     JSON Key: "name"
 *     JSON String: "barney"
 *
 * Copyright (c) 2014 Robert Poor <rdpoor@gmail.com>
 *
 * Jansson is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <jansson.h>
#include <assert.h>
#include <string.h>
#include "jwt.h"
#include "base64url.h"

/* forward refs */
void print_json(json_t *root);
void print_json_aux(json_t *element, int indent);
void print_json_indent(int indent);
const char *json_plural(int count);
void print_json_object(json_t *element, int indent);
void print_json_array(json_t *element, int indent);
void print_json_string(json_t *element, int indent);
void print_json_integer(json_t *element, int indent);
void print_json_real(json_t *element, int indent);
void print_json_true(json_t *element, int indent);
void print_json_false(json_t *element, int indent);
void print_json_null(json_t *element, int indent);

void print_json(json_t *root) {
    print_json_aux(root, 0);
}

void print_json_aux(json_t *element, int indent) {
    switch (json_typeof(element)) {
    case JSON_OBJECT:
        print_json_object(element, indent);
        break;
    case JSON_ARRAY:
        print_json_array(element, indent);
        break;
    case JSON_STRING:
        print_json_string(element, indent);
        break;
    case JSON_INTEGER:
        print_json_integer(element, indent);
        break;
    case JSON_REAL:
        print_json_real(element, indent);
        break;
    case JSON_TRUE:
        print_json_true(element, indent);
        break;
    case JSON_FALSE:
        print_json_false(element, indent);
        break;
    case JSON_NULL:
        print_json_null(element, indent);
        break;
    default:
        fprintf(stderr, "unrecognized JSON type %d\n", json_typeof(element));
    }
}

void print_json_indent(int indent) {
    int i;
    for (i = 0; i < indent; i++) { putchar(' '); }
}

const char *json_plural(int count) {
    return count == 1 ? "" : "s";
}

void print_json_object(json_t *element, int indent) {
    size_t size;
    const char *key;
    json_t *value;

    print_json_indent(indent);
    size = json_object_size(element);

    printf("JSON Object of %ld pair%s:\n", size, json_plural(size));
    json_object_foreach(element, key, value) {
        print_json_indent(indent + 2);
        printf("JSON Key: \"%s\"\n", key);
        print_json_aux(value, indent + 2);
    }

}

void print_json_array(json_t *element, int indent) {
    size_t i;
    size_t size = json_array_size(element);
    print_json_indent(indent);

    printf("JSON Array of %ld element%s:\n", size, json_plural(size));
    for (i = 0; i < size; i++) {
        print_json_aux(json_array_get(element, i), indent + 2);
    }
}

void print_json_string(json_t *element, int indent) {
    print_json_indent(indent);
    printf("JSON String: \"%s\"\n", json_string_value(element));
}

void print_json_integer(json_t *element, int indent) {
    print_json_indent(indent);
    printf("JSON Integer: \"%" JSON_INTEGER_FORMAT "\"\n", json_integer_value(element));
}

void print_json_real(json_t *element, int indent) {
    print_json_indent(indent);
    printf("JSON Real: %f\n", json_real_value(element));
}

void print_json_true(json_t *element, int indent) {
    (void)element;
    print_json_indent(indent);
    printf("JSON True\n");
}

void print_json_false(json_t *element, int indent) {
    (void)element;
    print_json_indent(indent);
    printf("JSON False\n");
}

void print_json_null(json_t *element, int indent) {
    (void)element;
    print_json_indent(indent);
    printf("JSON Null\n");
}

/*
 * Parse text into a JSON object. If text is valid JSON, returns a
 * json_t structure, otherwise prints and error and returns null.
 */
json_t *load_json(const char *text) {
    json_t *root;
    json_error_t error;

    root = json_loads(text, 0, &error);

    if (root) {
        return root;
    } else {
        fprintf(stderr, "json error on line %d: %s\n", error.line, error.text);
        return (json_t *)0;
    }
}

char *
jwt_encode(json_t *claims, jwa_t alg, sign_funcp sfunc)
{
    size_t hlen, clen, slen;
    char *jwt = NULL;
    char *head_e;
    char *claims_e;
    assert (NULL != claims);



    json_t *head_j = json_object();
    json_object_set_new(head_j, "alg", json_string("ES256"));

    char *head_s = json_dumps(head_j, 0);

    printf ("Header: %s\n", head_s);

    hlen = base64url_encode_alloc (head_s, strlen(head_s), &head_e);

    printf ("Encoded header: %s\n", head_e);

    char *claims_s = json_dumps(claims, 0);

    printf ("Claims to encode: %s\n", claims_s);

    clen = base64url_encode_alloc (claims_s, strlen(claims_s), &claims_e);

    printf ("Encoded claims: %s\n", claims_e);

    char *sign_input = malloc(hlen + 1 +clen + 1);
    assert (NULL != sign_input);

    strcpy (sign_input, head_e);
    sign_input[hlen] = '.';

    printf ("Sign input1: %s\n", sign_input);

    strcpy (&sign_input[hlen + 1], claims_e);

    sign_input[hlen + 1 + clen] = '.';

    printf ("Sign input2: %s\n", sign_input);

    return sign_input;
}

size_t
json2b64url (const json_t *j, char **out)
{
    assert (NULL != j);

    size_t s = 0;
    char *str;

    if (str = json_dumps(j, 0))
    {
        s = base64url_encode_alloc (str, strlen(str), out);

        free (str);
    }

    return s;
}

json_t *
b64url2json (char *encoded, size_t len)
{
    assert (NULL != encoded);

    char *str;
    size_t d_len;
    json_t *j = NULL;

    json_error_t jerr;

    d_len = base64url_decode_alloc (encoded, len, &str);

    if (d_len <= 0)
        return ;

    j = json_loadb(str, d_len, 0, &jerr);

    if (!j)
        printf("%s\n", jerr.text);

    free (str);

    return j;

}


/*
 * Print a prompt and return (by reference) a null-terminated line of
 * text.  Returns NULL on eof or some error.
 */
char *read_line(char *line, int max_chars) {
    printf("Type some JSON > ");
    fflush(stdout);
    return fgets(line, max_chars, stdin);
}

/* ================================================================
 * main
 */

void
test_json()
{
    json_t *obj = json_object();
    json_t *obj2 = json_object();

    json_object_set_new(obj, "Version", json_integer(42));
    json_object_set_new(obj2, "Crazy!", json_integer(42));

    json_object_set_new(obj, "Embedded", obj2);

    char *str = json_dumps(obj, JSON_ENSURE_ASCII);

    printf("%s\n", str);

}

#define MAX_CHARS 4096

int main(int argc, char *argv[]) {
    char line[MAX_CHARS];

    if (argc != 1) {
        fprintf(stderr, "Usage: %s\n", argv[0]);
        exit(-1);
    }

    while (read_line(line, MAX_CHARS) != (char *)NULL) {

        /* parse text into JSON structure */
        json_t *root = load_json(line);

        if (root) {
            /* print and release the JSON structure */
            print_json(root);
            json_decref(root);
        }
    }

    return 0;
}
