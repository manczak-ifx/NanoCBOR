/*
 * SPDX-License-Identifier: CC0-1.0
 */

#include <argp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "auth.h"
#include "suit_manifest_decoder.h"
#include "suit_print.h"

#define CBOR_READ_BUFFER_BYTES 4096

static const struct argp_option cmdline_options[] = {
    { "pretty", 'p', 0, OPTION_ARG_OPTIONAL,
      "Produce pretty printing with newlines and indents", 0 },
    { "input", 'f', "input", 0, "Input file, - for stdin", 0 },
    { 0 },
};

struct arguments {
    bool pretty;
    char *input;
};

static struct arguments _args = { false, NULL };

static uint8_t buffer[CBOR_READ_BUFFER_BYTES];

static error_t _parse_opts(int key, char *arg, struct argp_state *state)
{
    struct arguments *arguments = state->input;
    switch (key) {
    case 'p':
        arguments->pretty = true;
        break;
    case 'f':
        arguments->input = arg;
        break;
    case ARGP_KEY_END:
        if (!arguments->input) {
            argp_usage(state);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct argp arg_parse
        = { cmdline_options, _parse_opts, NULL, NULL, NULL, NULL, NULL };
    argp_parse(&arg_parse, argc, argv, 0, 0, &_args);

    FILE *fp = stdin;

    if (_args.input == NULL) {
        return -1;
    }

    if (strcmp(_args.input, "-") != 0) {
        fp = fopen(_args.input, "rbe");
    }

    if (!fp) {
        fprintf(stderr, "Unable to open input: %s\n", _args.input);
        return -1;
    }

    size_t len = fread(buffer, 1, sizeof(buffer), fp);

    fclose(fp);

    const uint8_t *manifest = NULL;
    size_t manifest_len = 0;
    suit_auth_result_t auth_result = suit_manifest_authenticate(
        buffer, len, &manifest, &manifest_len);
    if (auth_result != SUIT_AUTH_OK) {
        fprintf(stderr, "Manifest authentication failed (%d)\n", auth_result);
        return -1;
    }

    printf("Manifest authenticated, decoding %lu bytes:\n",
           (long unsigned)manifest_len);

    suit_print_set_pretty(_args.pretty);
    if (suit_manifest_decode(manifest, manifest_len) == SUIT_DECODE_ERROR) {
        fprintf(stderr, "Manifest decoding failed\n");
        return -1;
    }

    return 0;
}
