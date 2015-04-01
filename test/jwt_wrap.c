#include "config.h"
#include <jansson.h>
#include <string.h>
#include <stdlib.h>
#include <argp.h>
#include <assert.h>
#include <libcryptoauth.h>
#include "../libjosec.h"

const char *argp_program_version =
  "jwt-wrap 0.1";
const char *argp_program_bug_address =
  "<bugs@cryptotronix.com>";

/* Program documentation. */
static char doc[] =
  "Builds JWTs";

/* A description of the arguments we accept. */
static char args_doc[] = "";

/* Number of required args */
#define NUM_ARGS 0

/* The options we understand. */
static struct argp_option options[] = {
  {"verbose",  'v', 0,      0,  "Produce verbose output" },
  {"quiet",    'q', 0,      0,  "Don't produce any output" },
  {"silent",   's', 0,      OPTION_ALIAS },
  {"hardware", 'h', 0,      0,  "Use hardware crypto" },
  {"alg",      'a', "ALGORITHM", 0,  "JWA algorithm type"},
  {"key",      'k', "KEYFILE", 0,  "Gcrypt sexp private Keyfile"},
  {"display",  'd', "DISPLAY", 0,
   "DISPLAY option for the result" },
  {"json",     'j', "JSON", 0,
   "JSON FILE which will be the claims instead of stdin" },
  { 0 }
};

/* keyfile */
char *key_f;

/* Used by main to communicate with parse_opt. */
struct arguments
{
  char *args[NUM_ARGS];                /* arg1 & arg2 */
  int silent, verbose, hardware;
  FILE *input_file;
  char *display;
  jwa_t alg;
};

/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  struct arguments *arguments = state->input;

  switch (key)
    {
    case 'q': case 's':
      arguments->silent = 1;
      break;
    case 'v':
      arguments->verbose = 1;
      break;
    case 'h':
      arguments->hardware = 1;
      break;
    case 'k':
        key_f = arg;
        break;
    case 'j':
      if (NULL == (arguments->input_file = fopen (arg, "r")))
          argp_usage (state);

      break;
    case 'd':
      arguments->display = arg;
      break;

    case 'a':
        arguments->alg = jwa2enum (arg);
        break;

    case ARGP_KEY_ARG:
      if (state->arg_num >= NUM_ARGS)
        /* Too many arguments. */
        argp_usage (state);

      arguments->args[state->arg_num] = arg;

      break;

    case ARGP_KEY_END:
      if (state->arg_num < NUM_ARGS)
        /* Not enough arguments. */
        argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc };


json_t *
file2json (FILE *fp)
{
    json_error_t jerr;
    int rc = -1;
    json_t *j = NULL;

    assert (fp != NULL);

    if (0 == (j = json_loadf (fp, 0, &jerr)))
    {
        fprintf(stderr, "Failed to parse JSON file: %s\n", jerr.text);
    }

    fclose (fp);

    return j;

}

char *
f2jwt (FILE *fp, jwa_t alg, sign_funcp sfunc)
{
    int rc = -1;
    json_t *j;
    char *jwt;

    if (NULL == (j = file2json (fp)))
        return NULL;

    jwt = jwt_encode (j, alg, sfunc);

    json_decref (j);

    return jwt;

}


static int
soft_sign (const uint8_t *to_sign, size_t len,
      jwa_t alg, void *cookie,
      uint8_t **out, size_t *out_len)
{

    assert (NULL != key_f);

    int rc = -1;
    uint8_t *hash;
    gcry_sexp_t key, sig, digest;

    const unsigned int DLEN = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
    hash = malloc (DLEN);
    assert (NULL != hash);

    gcry_md_hash_buffer (GCRY_MD_SHA256, hash, to_sign, len);

    rc = gcry_sexp_build (&digest, NULL,
                          "(data (flags raw)\n"
                          " (value %b))",
                          DLEN, hash);

    if (rc)
        goto OUT;


    if (rc = lca_load_signing_key (key_f, &key))
        goto DIG;




    /* if (show_digest) */
    /* { */
    /*     lca_set_log_level (DEBUG); */
    /*     lca_print_sexp (digest); */
    /*     lca_set_log_level (INFO); */
    /* } */


    if (rc = gcry_pk_sign (&sig, digest, key))
        goto KEY;

    lca_print_sexp (sig);

    struct lca_octet_buffer signature = lca_sig2buf (&sig);

    if (NULL != signature.ptr)
    {
        *out = signature.ptr;
        *out_len = signature.len;
        rc = 0;
    }

    gcry_free (sig);


KEY:
    gcry_free (key);
DIG:
    gcry_free (digest);
OUT:
    free (hash);
    return rc;
}

int
main (int argc, char **argv)
{
  struct arguments arguments;
  int rc = -1;
  char *jwt;

  /* Default values. */
  arguments.silent = 0;
  arguments.verbose = 0;
  arguments.hardware = 0;
  arguments.input_file = stdin;
  arguments.display = "sexp";
  arguments.alg = NONE;
  key_f = NULL;

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  lca_init();

  if (!arguments.hardware)
      jwt = f2jwt (arguments.input_file, arguments.alg, soft_sign);

  if (NULL == jwt)
      return -3;
  else
      printf ("%s\n", jwt);

  exit (rc);
}
