%code top{
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include "pxed_config.h"

static int noboot = 0;
static char tftp_root[64];
static int config_err = 0;
static struct boot_option b_opt;
const struct boot_option *bopt;
extern int lineno;
}

%union {
	int intval;
	char *strval;
}

%code {
extern int yylineno;
extern char *yytext;
int yylex(void);
int yyerror(const char *s);
static int file_ok(const char *filename);
}


%token <intval> NUMBER
%token <strval>	WORD
%token <strval>	PHRASE
%token <strval>	PATH
%token <strval>	DIRECT

%token	TX86_64_EFI TX86_BIOS TIA64_EFI NL LOG COMMENT
%left	DESC BOOT_FILE TFTP_ROOT TMOUT PROMPT
%nonassoc	SETTO

%%

lines: /* empty */
	| lines line
	;

line:	NL
	| COMMENT NL
	| tftp_root NL
	| logfile NL
	| timeout NL
	| prompt NL
	| bspec NL {
		if(file_ok(bopt->bitems[noboot].bootfile)) {
			b_opt.bitems[noboot].index = 0x3001 + noboot;
			noboot++;
		} else {
			fprintf(stderr, "An Invalid File Boot Specification: %s," \
					" ignored.\n",
					b_opt.bitems[noboot].bootfile);
			config_err = 1;
		}
	}
	;

logfile: LOG SETTO PATH {strncpy(b_opt.logfile, $3, MAX_PATH);}
       ;

bspec:	client desc bootfile
	;

client:	TX86_64_EFI {b_opt.bitems[noboot].clarch = X86_64_EFI;}
	| TX86_BIOS {b_opt.bitems[noboot].clarch = X86_BIOS;}
	| TIA64_EFI {b_opt.bitems[noboot].clarch = IA64_EFI;}
	;

bootfile: BOOT_FILE SETTO PATH {strncpy(b_opt.bitems[noboot].bootfile, $3, MAX_PATH);}
	| BOOT_FILE SETTO WORD {strncpy(b_opt.bitems[noboot].bootfile, $3, MAX_PATH);}
	;

desc:	DESC SETTO WORD {strncpy(b_opt.bitems[noboot].desc, $3, MAX_PHRASE);}
	| DESC SETTO PHRASE {strncpy(b_opt.bitems[noboot].desc, $3, MAX_PHRASE);}
	;

tftp_root: TFTP_ROOT SETTO PATH {strncpy(tftp_root, $3, sizeof(tftp_root));}
	 | TFTP_ROOT SETTO DIRECT {strncpy(tftp_root, $3, sizeof(tftp_root));}
	;

timeout: TMOUT SETTO NUMBER {b_opt.timeout = $3;}
	;

prompt:	PROMPT SETTO PHRASE {strncpy(b_opt.prompt, $3, sizeof(b_opt.prompt));}
	| PROMPT SETTO WORD {strncpy(b_opt.prompt, $3, sizeof(b_opt.prompt));}
	;
%%

static int file_ok(const char *filename)
{
	int retv, sysret, len;
	struct stat file_state;
	char fname[256];
	FILE *fin;

	retv = 0;
	if (!filename || *filename == 0)
		return retv;

	len = strlen(tftp_root);
	if (len > 0) {
		strcpy(fname, tftp_root);
		if (fname[len-1] != '/' && *filename != '/')
			strcat(fname, "/");
		strcat(fname, filename);
	} else
		strcpy(fname, filename);
	sysret = stat(fname, &file_state);
	if (sysret == -1)
		goto exit_10;
	if (!S_ISREG(file_state.st_mode))
		goto exit_10;
	fin = fopen(fname, "rb");
	if (!fin)
		goto exit_10;
	fclose(fin);
	retv = 1;

exit_10:
       retv = 1;
	return retv;
}

extern FILE *yyin;
extern int yyparse(void);

int pxed_config(const char *confname, int verbose)
{
	int retc, retv, i;
	struct boot_item *btm;

	retv = 0;
	bopt = &b_opt;
	b_opt.logfile[0] = 0;
	yyin = fopen(confname, "rb");
	if (!yyin) {
		fprintf(stderr, "Cannot open config file \"%s\": %s\n", confname,
				strerror(errno));
		return -1;
	}
	retc = yyparse();
	fclose(yyin);
	if (retc) {
		fprintf(stderr, "Configuration File Error: %d\n", retc);
		return -2;
	}
	b_opt.n_bitems = noboot;

	if (verbose == 0)
		return 0;

	printf("TFTP Root: %s\n", tftp_root);
	printf("Timeout: %d\n", bopt->timeout);
	printf("Prompt: %s\n", bopt->prompt);
	printf("Number boot items: %d\n", noboot);
	printf("Log File: %s\n", bopt->logfile);
	for (i = 0, btm = b_opt.bitems; i < noboot; i++, btm++) {
		printf("Boot Item: %d:\n", i+1);
		printf("\tBoot Server Type: %04hX\n", btm->index);
		printf("\tClient Type: %d\n", (int)btm->clarch);
		printf("\tDescription: %s\n", btm->desc);
		printf("\tBoot File: %s\n", btm->bootfile);
	}
	return retv;
}

int yyerror(const char *s)
{
	int retv;

	retv = fprintf(stderr, "%s: Line %d, %s\n", s, lineno, yytext);
	return retv;
}
