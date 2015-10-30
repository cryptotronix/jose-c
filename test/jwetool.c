/* -*- mode: c; c-file-style: "gnu" -*- */
#include "config.h"
#include <jansson.h>
#include <string.h>
#include <stdlib.h>
#include <argp.h>
#include <assert.h>
#include "../libjosec.h"


const char *argp_program_version =
  "jwe-tool 0.1";
const char *argp_program_bug_address =
  "<bugs@cryptotronix.com>";

/* Program documentation. */
static char doc[] =
  "Encrypts and decrypts JWEs";

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
  {"key",      'k', "KEYFILE", 0,  "Public Key file"},
  {"format",   'f', "KEYFILE FORMAT", 0,  "Format of keyfile"},
  {"display",  'd', "DISPLAY", 0,
   "DISPLAY option for the result" },
  {"jwt",     'j', "JWT", 0,
   "JWT FILE which will be read instead of stdin" },
  { 0 }
};

/* Used by main to communicate with parse_opt. */
struct arguments
{
  char *args[NUM_ARGS];                /* arg1 & arg2 */
  int silent, verbose, hardware;
  FILE *input_file;
  char *display;
  jwa_t alg;
  kf_format_t key_format;
  char *key_file;
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
        arguments->key_file = arg;
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


char *
file2jwt (FILE *fp)
{

    size_t MAX = 1024 * 10;
    char *jwt = malloc (MAX);
    assert (NULL != jwt);
    int l;

    if (0 == (l = fread(jwt, 1, MAX, fp)))
        return NULL;
    else
    {
        fprintf (stderr, "Load len: %d\n", l);
        return jwt;
    }

}

json_t *
jwk_load (const char *f, kf_format_t format)
{
    json_t *jwk;
    assert (NULL != f);

    if (GCRYPT == format)
    {

        gcry_sexp_t key;
        if (lca_load_signing_key (f, &key))
            return NULL;

        jwk = gcry_pubkey2jwk (&key);

        //json_dumpf (jwk, stdout, 0);

        gcry_sexp_release (key);

    }
    else if (JWK == format)
    {
        json_error_t jerr;
        FILE *fp;

        if ((fp = fopen (f, "r")))
            return NULL;

        if (0 == (jwk = json_loadf (fp, 0, &jerr)))
        {
            fprintf(stderr, "Failed to parse JSON file: %s\n", jerr.text);
        }

        fclose (fp);

    }

    return jwk;
}


int
parse_jwt (FILE *fp, const char *keyfile, kf_format_t format)
{
    int rc = -1;
    char *jwt;
    json_t *head, *claims, *jwk= NULL;

    jwt = file2jwt (fp);

    if (!jwt)
        return rc;

    if (0 == jwt_split (jwt, &head, &claims))
    {
        printf ("Head: ");
        json_dumpf (head, stdout, 0);
        printf ("\n");

        printf ("Claims: ");
        json_dumpf (claims, stdout, 0);
        printf ("\n");


        if (NULL != keyfile)
        {
            jwk = jwk_load (keyfile, format);
        }

        rc = jwt_verify (jwk, jwt);

        printf ("RC: %d\n", rc);

    }

    free (jwt);

    return rc;
}
int
main (int argc, char **argv)
{
  struct arguments arguments;
  int rc = -1;

  /* Default values. */
  arguments.silent = 0;
  arguments.verbose = 0;
  arguments.hardware = 0;
  arguments.input_file = stdin;
  arguments.display = "sexp";
  arguments.alg = NONE;
  arguments.key_format = GCRYPT;
  arguments.key_file = NULL;

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  argp_parse (&argp, argc, argv, 0, 0, &arguments);

  assert (NULL != gcry_check_version (NULL));

  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);


  if (!arguments.hardware)
      rc = parse_jwt (arguments.input_file, arguments.key_file, arguments.key_format);

  exit (rc);
}
