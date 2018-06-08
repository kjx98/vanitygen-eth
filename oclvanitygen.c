/*
 * Vanitygen ETH, vanity ETH address generator
 * Copyright (C) 2018 <jkuang@21cn.com>
 *
 * Vanitygen is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * Vanitygen is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Vanitygen.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <assert.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

#include "oclengine.h"
#include "pattern.h"
#include "util.h"

char ticker[10];

const char *version = VANITYGEN_VERSION;
const int debug = 0;


void
usage(const char *name)
{
	fprintf(stderr,
"oclVanitygen %s (" OPENSSL_VERSION_TEXT ")\n"
"Usage: %s [-vqrik1NTS] [-d <device>] [-f <filename>|-] [<pattern>...]\n"
"Generates a bitcoin receiving address matching <pattern>, and outputs the\n"
"address and associated private key.  The private key may be stored in a safe\n"
"location or imported into a bitcoin client to spend any balance received on\n"
"the address.\n"
"By default, <pattern> is interpreted as an exact prefix.\n"
"By default, if no device is specified, and the system has exactly one OpenCL\n"
"device, it will be selected automatically, otherwise if the system has\n"
"multiple OpenCL devices and no device is specified, an error will be\n"
"reported.  To use multiple devices simultaneously, specify the -D option for\n"
"each device.\n"
"\n"
"Options:\n"
"-v            Verbose output\n"
"-q            Quiet output\n"
"-k            Keep pattern and continue search after finding a match\n"
"-1            Stop after first match\n"
"-a <amount>   Stop after generating <amount> addresses/keys\n"
"-Y <version>  Specify private key version (-X provides public key)\n"
"-P <pubkey>   Use split-key method with <pubkey> as base public key\n"
"-p <platform> Select OpenCL platform\n"
"-d <device>   Select OpenCL device\n"
"-D <devstr>   Use OpenCL device, identified by device string\n"
"              Form: <platform>:<devicenumber>[,<options>]\n"
"              Example: 0:0,grid=1024x1024\n"
"-S            Safe mode, disable OpenCL loop unrolling optimizations\n"
"-w <worksize> Set work items per thread in a work unit\n"
"-t <threads>  Set target thread count per multiprocessor\n"
"-g <x>x<y>    Set grid size\n"
"-b <invsize>  Set modular inverse ops per thread\n"
"-V            Enable kernel/OpenCL/hardware verification (SLOW)\n"
"-f <file>     File containing list of patterns, one per line\n"
"              (Use \"-\" as the file name for stdin)\n"
"-o <file>     Write pattern matches to <file>\n"
"-s <file>     Seed random number generator from <file>\n"
"-Z <prefix>   Private key prefix in hex (vipco.in)\n"
"-z            Format output of matches in CSV(disables verbose mode)\n"
"              Output as [COIN],[PREFIX],[ADDRESS],[PRIVKEY]\n",
version, name);
}

#define MAX_DEVS 32
#define MAX_FILE 4

int
main(int argc, char **argv)
{
	int opt;
	int platformidx = -1, deviceidx = -1;
	char *seedfile = NULL;
	char **patterns, *pend;
	int verbose = 1;
	int npatterns = 0;
	int nthreads = 0;
	int worksize = 0;
	int nrows = 0, ncols = 0;
	int invsize = 0;
	int remove_on_match = 1;
	int only_one = 0;
	int numpairs = 0;
	int csv = 0;
	int verify_mode = 0;
	int safe_mode = 0;
	vg_context_t *vcp = NULL;
	vg_ocl_context_t *vocp = NULL;
	EC_POINT *pubkey_base = NULL;
	const char *result_file = NULL;
	char *devstrs[MAX_DEVS];
	int ndevstrs = 0;
	int opened = 0;
	char privkey_prefix[32];
	int privkey_prefix_length = 0;

	FILE *pattfp[MAX_FILE], *fp;
	int npattfp = 0;
	int pattstdin = 0;

	int i;

	while ((opt = getopt(argc, argv,
			     "vqk1zp:P:d:w:t:g:b:VSh?f:o:s:D:Z:a:")) != -1) {
		switch (opt) {
		case 'v':
			verbose = 2;
			break;
		case 'q':
			verbose = 0;
			break;
		case 'k':
			remove_on_match = 0;
			break;
		case '1':
			only_one = 1;
			break;
		case 'a':
			remove_on_match = 0;
			numpairs = atoi(optarg);
			break;
		case 'z':
		      csv = 1;
		      break;
		case 'p':
			platformidx = atoi(optarg);
			break;
		case 'd':
			deviceidx = atoi(optarg);
			break;
		case 'w':
			worksize = atoi(optarg);
			if (worksize == 0) {
				fprintf(stderr, "Invalid work size '%s'\n", optarg);
				return 1;
			}
			break;
		case 't':
			nthreads = atoi(optarg);
			if (nthreads == 0) {
				fprintf(stderr, "Invalid thread count '%s'\n", optarg);
				return 1;
			}
			break;
		case 'g':
			nrows = 0;
			ncols = strtol(optarg, &pend, 0);
			if (pend && *pend == 'x') {
				nrows = strtol(pend+1, NULL, 0);
			}
			if (!nrows || !ncols) {
				fprintf(stderr, "Invalid grid size '%s'\n", optarg);
				return 1;
			}
			break;
		case 'b':
			invsize = atoi(optarg);
			if (!invsize) {
				fprintf(stderr, "Invalid modular inverse size '%s'\n", optarg);
				return 1;
			}
			if (invsize & (invsize - 1)) {
				fprintf(stderr, "Modular inverse size must be a power of 2\n");
				return 1;
			}
			break;
		case 'V':
			verify_mode = 1;
			break;
		case 'S':
			safe_mode = 1;
			break;
		case 'D':
			if (ndevstrs >= MAX_DEVS) {
				fprintf(stderr, "Too many OpenCL devices (limit %d)\n", MAX_DEVS);
				return 1;
			}
			devstrs[ndevstrs++] = optarg;
			break;
		case 'P': {
			if (pubkey_base != NULL) {
				fprintf(stderr, "Multiple base pubkeys specified\n");
				return 1;
			}
			EC_KEY *pkey = vg_exec_context_new_key();
			pubkey_base = EC_POINT_hex2point(EC_KEY_get0_group(pkey), optarg, NULL, NULL);
			EC_KEY_free(pkey);
			if (pubkey_base == NULL) {
				fprintf(stderr, "Invalid base pubkey\n");
				return 1;
			}
			break;
		}
		case 'f':
			if (npattfp >= MAX_FILE) {
				fprintf(stderr, "Too many input files specified\n");
				return 1;
			}
			if (!strcmp(optarg, "-")) {
				if (pattstdin) {
					fprintf(stderr, "ERROR: stdin specified multiple times\n");
					return 1;
				}
				fp = stdin;
			} else {
				fp = fopen(optarg, "r");
				if (!fp) {
					fprintf(stderr, "Could not open %s: %s\n", optarg, strerror(errno));
					return 1;
				}
			}
			pattfp[npattfp] = fp;
			npattfp++;
			break;
		case 'o':
			if (result_file) {
				fprintf(stderr, "Multiple output files specified\n");
				return 1;
			}
			result_file = optarg;
			break;
		case 's':
			if (seedfile != NULL) {
				fprintf(stderr, "Multiple RNG seeds specified\n");
				return 1;
			}
			seedfile = optarg;
			break;
		case 'Z':
			assert(strlen(optarg) % 2 == 0);
			privkey_prefix_length = strlen(optarg)/2;
			if ( privkey_prefix_length > 32 ) privkey_prefix_length = 32;
			for (size_t i = 0; i < privkey_prefix_length; i++) {
				int value; // Can't sscanf directly to char array because of overlapping on Win32
				sscanf(&optarg[i*2], "%2x", &value);
				privkey_prefix[privkey_prefix_length - 1 - i] = value;
			}
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (seedfile) {
		opt = -1;
#if !defined(_WIN32)
		{	struct stat st;
			if (!stat(seedfile, &st) && (st.st_mode & (S_IFBLK|S_IFCHR))) opt = 32;
		}
#endif
		opt = RAND_load_file(seedfile, opt);
		if (!opt) {
			fprintf(stderr, "Could not load RNG seed %s\n", optarg);
			return 1;
		}
		if (verbose > 0) {
			fprintf(stderr, "Read %d bytes from RNG seed file\n", opt);
		}
	}

    vcp = vg_prefix_context_new();

	vcp->vc_verbose = verbose;
	vcp->vc_result_file = result_file;
	vcp->vc_remove_on_match = remove_on_match;
	vcp->vc_only_one = only_one;
	vcp->vc_numpairs = numpairs;
	vcp->vc_csv = csv;
	vcp->vc_pubkey_base = pubkey_base;
	memcpy(vcp->vc_privkey_prefix, privkey_prefix, privkey_prefix_length);
	vcp->vc_privkey_prefix_length = privkey_prefix_length;

	vcp->vc_output_match = vg_output_match_console;
	vcp->vc_output_timing = vg_output_timing_console;

	if (!npattfp) {
		if (optind >= argc) {
			usage(argv[0]);
			return 1;
		}
		patterns = &argv[optind];
		npatterns = argc - optind;

		if (!vg_context_add_patterns(vcp, (const char ** const) patterns, npatterns))
            return 1;
	}

	for (i = 0; i < npattfp; i++) {
		fp = pattfp[i];
		if (!vg_read_file(fp, &patterns, &npatterns)) {
			fprintf(stderr, "Failed to load pattern file\n");
			return 1;
		}
		if (fp != stdin) fclose(fp);

		if (!vg_context_add_patterns(vcp, (const char ** const) patterns, npatterns))
            return 1;
	}

	if (!vcp->vc_npatterns) {
		fprintf(stderr, "No patterns to search\n");
		return 1;
	}

	if (ndevstrs) {
		for (opt = 0; opt < ndevstrs; opt++) {
			vocp = vg_ocl_context_new_from_devstr(vcp, devstrs[opt], safe_mode, verify_mode);
			if (!vocp) {
				fprintf(stderr, "Could not open device '%s', ignoring\n", devstrs[opt]);
			} else {
				opened++;
			}
		}
	} else {
		vocp = vg_ocl_context_new(vcp, platformidx, deviceidx,
					  safe_mode, verify_mode, worksize, nthreads,
					  nrows, ncols, invsize);
		if (vocp) opened++;
	}

	if (!opened) {
		vg_ocl_enumerate_devices();
		return 1;
	}

	opt = vg_context_start_threads(vcp);
	if (opt) return 1;

	vg_context_wait_for_completion(vcp);
	vg_ocl_context_free(vocp);
	return 0;
}
