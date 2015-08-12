/* -*- mode: c; c-file-style: "gnu" -*- */

#include "config.h" /* Only needed for this autotools project, not
                     * real production code */
#include <unistd.h>
#include <sys/socket.h>
#include <stdio.h>
#include <assert.h>
#include <syslog.h>
#include <argp.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <sys/un.h>
#include <sys/types.h>  /* Type definitions used by many programs */
#include <errno.h>      /* Declares errno and defines error constants */
#include <gcrypt.h>
#include <jansson.h>
#include "../src/jwk.h"

#define TC_NUM_ARGS 1

typedef struct tc_argsd_t
{
  char *args[TC_NUM_ARGS + 1];
  int silent, verbose;
  char *jwk_file, *signature;
} tc_argsd_t;

const char *argp_program_version = PACKAGE_VERSION;

const char *argp_program_bug_address = PACKAGE_BUGREPORT;

/* Program documentation. */
static char doc[] =
  "Utility to sign,verify,create JWK\n"
  "Valid commands: sign verify create"
  "\n\n"
  "EXAMPLE USAGE:\n"
  "jwkutil create >> jwk.json"
  "jwkutil sign --jwk key.json"
  "jwkutil verify --jwk key.json --sig BSUZPW9a-IZuCbnSX6fYZg1W0zn4Xsj018Jup0pYENhF1o6EzC_fOyBHEsLCbH2C0ekm1AQ6fU5JQLPVT_XlrA";

/* A description of the arguments we accept. */
static char args_doc[] = "command";

/* The options we understand. */
static struct argp_option options[] = {
  {"verbose",  'v', 0,      0,  "Produce verbose output", 0 },
  {"silent",   's', 0,      OPTION_ALIAS , 0, 0},
  {"quietish", 'q', 0,      0,  "Small amount of output", 0 },
  {"jwk",      'j', "JWK to laod", 0,  "The JWK to load for signing or verify"},
  {"sig",      'g', "Signature", 0,  "The base64URL encoded signature to verify"},
  { 0 }
};

/* Parse a single option. */
static error_t
parse_opt (int key, char *arg, struct argp_state *state)
{
  /* Get the input argument from argp_parse, which we
     know is a pointer to our arguments structure. */
  tc_argsd_t *arguments = state->input;

  switch (key)
    {
    case 's':
      arguments->silent = 1;
      break;
    case 'v':
      arguments->verbose = 1;
      break;
    case 'j':
      arguments->jwk_file = arg;
      break;
    case 'g':
      arguments->signature = arg;
      break;
    case ARGP_KEY_ARG:
      if (state->arg_num >= TC_NUM_ARGS)
        /* Too many arguments. */
        argp_usage (state);
      else
        arguments->args[state->arg_num] = arg;

      break;

    case ARGP_KEY_END:
      if (state->arg_num < TC_NUM_ARGS)
        /* Not enough arguments. */
        argp_usage (state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
    }
  return 0;
}

/* Our argp parser. */
static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

static void
init_argp (tc_argsd_t *args)
{
  /* Default values. */
  args->silent = 0;
  args->verbose = 0;
  args->jwk_file = NULL;
  args->signature = NULL;
}

static jwk_init (void)
{

  /*GCRY_THREAD_OPTION_PTH_IMPL;*/

  if (gcry_control (GCRYCTL_INITIALIZATION_FINISHED_P))
    {
      exit (EXIT_FAILURE);
    }

  gcry_control (GCRYCTL_ENABLE_M_GUARD);

  /* Version check should be the very first call because it
     makes sure that important subsystems are initialized. */
  if (!gcry_check_version (GCRYPT_VERSION))
    {
      fputs ("libgcrypt version mismatch\n", stderr);
      exit (EXIT_FAILURE);
    }

  if (gcry_control (GCRYCTL_USE_SECURE_RNDPOOL))
    {
      exit (EXIT_FAILURE);
    }
  /* We don't want to see any warnings, e.g. because we have not yet
     parsed program options which might be used to suppress such
     warnings. */
  if (gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN))
    {
      exit (EXIT_FAILURE);
    }

  /* ... If required, other initialization goes here.  Note that the
     process might still be running with increased privileges and that
     the secure memory has not been initialized.  */

  /* Allocate a pool of 16k secure memory.  This make the secure memory
     available and also drops privileges where needed.  */
  if (gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0))
    {
      exit (EXIT_FAILURE);
    }

  /* It is now okay to let Libgcrypt complain when there was/is
     a problem with the secure memory. */
  if (gcry_control (GCRYCTL_RESUME_SECMEM_WARN))
    {
      exit (EXIT_FAILURE);
    }

  /* Tell Libgcrypt that initialization has completed. */
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

}
static void
show_sexp (const char *prefix, gcry_sexp_t a)
{
  char *buf;
  size_t size;

  fprintf (stderr, "%s: ", "keygen");
  if (prefix)
    fputs (prefix, stderr);
  size = gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, NULL, 0);
  buf = malloc (size);
  assert (buf);
  memset (buf, 0, size);

  gcry_sexp_sprint (a, GCRYSEXP_FMT_ADVANCED, buf, size);
  fprintf (stderr, "%.*s", (int)size, buf);
  free (buf);
}


static char *
gcry_prikey2jwk (gcry_sexp_t * pubkey)
{

    assert (NULL != pubkey);

    gcry_error_t  rc = -1;
    gcry_sexp_t sexp_q;
    gcry_mpi_t mpi_q;
    unsigned char *raw_q;
    size_t size_q;
    size_t d_b64_len;
    char *d_b64 = NULL;

    if (NULL == (sexp_q = gcry_sexp_find_token(*pubkey, "d", 0)))
        goto OUT;

    if (NULL == (mpi_q = gcry_sexp_nth_mpi (sexp_q, 1, GCRYMPI_FMT_USG)))
        goto FREE_Q;

    rc = gcry_mpi_aprint(GCRYMPI_FMT_USG, &raw_q, &size_q, mpi_q);
    if (rc)
        goto FREE_MPI_Q;

    if (0 == (d_b64_len = base64url_encode_alloc (raw_q, size_q, &d_b64)))
      goto FREE_MPI_Q;



    gcry_free (raw_q);

FREE_MPI_Q:
    gcry_mpi_release (mpi_q);
FREE_Q:
    gcry_sexp_release (sexp_q);
OUT:
    return d_b64;
}


static int
jwk_create (tc_argsd_t *arguments)
{

  int rc;
  gcry_sexp_t keyparm, key;
  json_t *jwk;

  rc = gcry_sexp_build (&keyparm, NULL,
                        "(genkey\n"
                        " (ecc\n"
                        "  (curve \"NIST P-256\")\n"
                        "  (flags param)"
                        "))");

  if (rc) return rc;

  rc = gcry_pk_genkey (&key, keyparm);

  if (rc) return rc;

  if (arguments->verbose)
    show_sexp ("Gen key:\n", key);

  gcry_sexp_release (keyparm);

  jwk = gcry_pubkey2jwk (&key);

  char *d = gcry_prikey2jwk (&key);

  assert (NULL != d);

  assert (0 == json_object_set (jwk, "d", json_string (d)));

  json_dumpf(jwk, stdout, JSON_INDENT(2));
  printf("\n");



  return rc;

}

int
jwk2prikey (const json_t *jwk, gcry_sexp_t *prikey)
{
    assert (NULL != jwk);
    assert (NULL != prikey);

    int rc = -1;
    json_t *j_d = json_object_get(jwk, "d");

    uint8_t *d;
    size_t d_len;

    if (NULL == j_d)
        return rc;

    d_len = base64url_decode_alloc (json_string_value (j_d),
                                    strlen (json_string_value (j_d)),
                                    (char **)&d);

    if (d_len <= 0 || d_len > 256)
        goto OUT;

    rc = gcry_sexp_build (prikey, NULL,
                          "(private-key\n"
                          " (ecdsa\n"
                          "  (curve \"NIST P-256\")\n"
                          "  (d %b)"
                          "))", d_len, d);

OUT:
    free (d);

    return rc;

}

static uint8_t*
sig2sigbuf (const gcry_sexp_t *sig, uint8_t **out, size_t *rs_len)
{
  assert (NULL != sig);
  assert (NULL != out);

  gcry_error_t  rc = -1;
  gcry_sexp_t sexp_r, sexp_s;
  gcry_mpi_t mpi_r, mpi_s;
  unsigned char *raw_r, *raw_s;
  size_t size_r, size_s;
  uint8_t *rs;


  if (NULL == (sexp_r = gcry_sexp_find_token(*sig, "r", 0)))
    goto OUT;

  if (NULL == (sexp_s = gcry_sexp_find_token(*sig, "s", 0)))
    goto FREE_R;

  if (NULL == (mpi_r = gcry_sexp_nth_mpi (sexp_r, 1, GCRYMPI_FMT_USG)))
    goto FREE_S;

  if (NULL == (mpi_s = gcry_sexp_nth_mpi (sexp_s, 1, GCRYMPI_FMT_USG)))
    goto FREE_MPI_R;

  rc = gcry_mpi_aprint(GCRYMPI_FMT_USG, &raw_r, &size_r, mpi_r);
  if (rc)
    goto FREE_MPI_S;

  rc = gcry_mpi_aprint(GCRYMPI_FMT_USG, &raw_s, &size_s, mpi_s);
  if (rc)
    goto FREE_RAW_R;

  rs = malloc (size_r+size_s);
  memset (rs, 0, size_r+size_s);

  memcpy (rs, raw_r, size_r);
  memcpy (rs+size_r, raw_s, size_s);

  *rs_len = size_r + size_s;

  rc = 0;

  gcry_free (raw_s);
 FREE_RAW_R:
  gcry_free (raw_r);
 FREE_MPI_S:
  gcry_mpi_release (mpi_s);
 FREE_MPI_R:
  gcry_mpi_release (mpi_r);
 FREE_S:
  gcry_sexp_release (sexp_s);
 FREE_R:
  gcry_sexp_release (sexp_r);
 OUT:
  if (rc == 0)
    return rs;
  else
    return NULL;

}


static int
jwk_sign (tc_argsd_t *arguments)
{

  char *line;
  size_t n = 0;
  json_t *jwk;
  gcry_sexp_t prikey, digest, signature;
  gcry_error_t  err;

  ssize_t line_s = getline(&line, &n, stdin);

  if (line_s <= 0)
    {
      fprintf (stderr, "Failed to read line\n");
      exit (EXIT_FAILURE);
    }

  jwk = json_load_file(arguments->jwk_file, 0, NULL);

  if (NULL == jwk)
    {
      fprintf(stderr, "failed to load JWK, invalid JSON?\n");
      exit (EXIT_FAILURE);
    }

  if (0 != jwk2prikey (jwk, &prikey))
    {
      fprintf(stderr, "failed to parse pub key in JWK\n");
      exit (EXIT_FAILURE);
    }

  if (arguments->verbose)
    printf("Signing: %s\n", line);

  const unsigned int DLEN = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
  uint8_t *dgst = malloc (DLEN);
  memset (dgst, 0, DLEN);

  gcry_md_hash_buffer (GCRY_MD_SHA256, dgst, line, line_s);

  assert (0 == gcry_sexp_build (&digest, NULL,
                                "(data (flags raw)\n"
                                " (value %b))",
                                DLEN, dgst));

  if ((err = gcry_pk_sign (&signature, digest, prikey)))
    {
      printf ("line %d: %s", __LINE__, gpg_strerror (err));
      exit (EXIT_FAILURE);
    }

  if (arguments->verbose)
    show_sexp ("Signature:\n", signature);

  uint8_t *rs;
  size_t rs_len;
  char *b64sig;
  rs = sig2sigbuf (&signature, &rs, &rs_len);
  assert (NULL != rs);

  base64url_encode_alloc (rs, rs_len, &b64sig);

  printf ("%s\n", b64sig);


  free (line);
  free (rs);
  free (b64sig);

}


static int
jwk_verify (tc_argsd_t *arguments)
{

  char *line;
  size_t n = 0;
  json_t *jwk;
  gcry_sexp_t pubkey, digest, signature;
  gcry_error_t  err;
  char *rawsig;

  ssize_t line_s = getline(&line, &n, stdin);

  if (line_s <= 0)
    {
      fprintf (stderr, "Failed to read line\n");
      exit (EXIT_FAILURE);
    }

  jwk = json_load_file(arguments->jwk_file, 0, NULL);

  if (NULL == jwk)
    {
      fprintf(stderr, "failed to load JWK, invalid JSON?\n");
      exit (EXIT_FAILURE);
    }

  if (0 != jwk2pubkey (jwk, &pubkey))
    {
      fprintf(stderr, "failed to parse pub key in JWK\n");
      exit (EXIT_FAILURE);
    }

  if (arguments->verbose)
    printf("Data to verify: %s\n", line);

  assert (0 == jws2sig (arguments->signature, &signature));



  const unsigned int DLEN = gcry_md_get_algo_dlen (GCRY_MD_SHA256);
  uint8_t *dgst = malloc (DLEN);
  memset (dgst, 0, DLEN);

  gcry_md_hash_buffer (GCRY_MD_SHA256, dgst, line, line_s);

  assert (0 == gcry_sexp_build (&digest, NULL,
                                "(data (flags raw)\n"
                                " (value %b))",
                                DLEN, dgst));

  int rc = gcry_pk_verify (signature, digest, pubkey);

  if (rc)
    printf("Signature FAILED\n");
  else
    printf("Signature VERIFIED\n");

  json_decref (jwk);
  free (line);

}



int
main(int argc, char *argv[])
{
  int rc = -1;

  tc_argsd_t arguments;

  init_argp (&arguments);

  /* Parse our arguments; every option seen by parse_opt will
     be reflected in arguments. */
  rc = argp_parse (&argp, argc, argv, 0, 0, &arguments);
  if (rc)
    {
      printf ("Bad args... exiting\n");
      return rc;
    }


  jwk_init();

  if (strcmp(arguments.args[0], "create") == 0)
    {
      rc = jwk_create (&arguments);
    }
  else if (strcmp(arguments.args[0], "sign") == 0)
    {
      if (arguments.jwk_file == NULL)
        {
          fprintf (stderr, "sign command requires JWK path as -f option\n");
          exit (EXIT_FAILURE);
        }
      rc = jwk_sign (&arguments);
    }
  else if (strcmp(arguments.args[0], "verify") == 0)
    {
      if (arguments.jwk_file == NULL)
        {
          fprintf (stderr, "sign command requires JWK path as -f option\n");
          exit (EXIT_FAILURE);
        }
      if (arguments.signature == NULL)
        {
          fprintf (stderr, "sign command requires b64url encoded signature as -g option\n");
          exit (EXIT_FAILURE);
        }

      rc = jwk_verify (&arguments);
    }
  else
    {
      fprintf(stderr, "Not a valid command, see --help\n");
      exit (EXIT_FAILURE);
    }



  exit (rc);

}
