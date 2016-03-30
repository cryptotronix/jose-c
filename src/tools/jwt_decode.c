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
#include <jansson.h>
#include <libjosec.h>
#include "../util.h"

#define TC_NUM_ARGS 0

typedef struct tc_argsd_t
{
  char *args[TC_NUM_ARGS + 1];
  int silent, verbose;
} tc_argsd_t;

const char *argp_program_version = PACKAGE_VERSION;

const char *argp_program_bug_address = PACKAGE_BUGREPORT;

/* Program documentation. */
static char doc[] =
  "Simple JWT parser\n\n"
  "Pass the JWT as stdin";

/* A description of the arguments we accept. */
static char args_doc[] = "";

/* The options we understand. */
static struct argp_option options[] = {
  {"verbose",  'v', 0,      0,  "Produce verbose output", 0 },
  {"silent",   's', 0,      OPTION_ALIAS , 0, 0},
  {"quietish", 'q', 0,      0,  "Small amount of output", 0 },
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
      goto OUT;
    }

  char *line = NULL;
  size_t n = 0;

  ssize_t line_s = getline(&line, &n, stdin);

  if (line_s <= 0)
    {
      fprintf (stderr, "Failed to read line\n");
      exit (EXIT_FAILURE);
    }

  char *jwt = trim(line);
  assert (jwt);

  json_t *header, *claims, *out;

  rc = jwt_decode (jwt, &header, &claims);

  if (rc)
    {
      fprintf (stderr, "%s: %d\n", "Failed to decode JWT", rc);
      goto OUT;
    }

  /* Package the decoded JWT into it's three parts */
  out = json_object();
  assert (NULL != out);

  assert (0 == json_object_set (out, "header", header));
  assert (0 == json_object_set (out, "claims", claims));

  rc = json_dumpf (out, stdout, JSON_INDENT(2) | JSON_PRESERVE_ORDER);
  if (rc)
    {
      fprintf (stderr, "%s: %d\n", "Failed to print response", rc);
      goto OUT;
    }

  printf ("\n");
  json_decref (out);
  free (line);
 OUT:
  exit (rc);

}
