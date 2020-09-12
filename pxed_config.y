%code top{
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "miscs.h"
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
%token <strval>	PATH
%token <strval>	WORD
%token <strval>	PHRASE
%token <strval>	DIRECT

%token	BOOT_FILE DESC TFTP_ROOT TMOUT PROMPT
%token	TX86_64_EFI TX86_BIOS TIA64_EFI

%%

specs:	/* empty */
        | spec
	| specs spec
	;


spec:	tftp_root
	| timeout
	| prompt
	| bspec {
		if(file_ok(bopt->bitems[noboot].bootfile)) {
			b_opt.bitems[noboot].svrtyp = 0x3001 + noboot;
			noboot++;
		} else {
			logmsg(LERR, "An Invalid File Specification: %s\n",
				b_opt.bitems[noboot].bootfile);
			config_err = 1;
		}
	}
	;

bspec:	bitem bitem bitem
	;

bitem:	TX86_64_EFI {b_opt.bitems[noboot].clarch = X86_64_EFI;}
	| TX86_BIOS {b_opt.bitems[noboot].clarch = X86_BIOS;}
	| TIA64_EFI {b_opt.bitems[noboot].clarch = IA64_EFI;}
	| BOOT_FILE '=' PATH {strncpy(b_opt.bitems[noboot].bootfile, $3, MAX_PATH);}
	| BOOT_FILE '=' WORD {strncpy(b_opt.bitems[noboot].bootfile, $3, MAX_PATH);}
	| DESC '=' WORD {strncpy(b_opt.bitems[noboot].desc, $3, MAX_PHRASE);}
	| DESC '=' PHRASE {strncpy(b_opt.bitems[noboot].desc, $3, MAX_PHRASE);}
	;

tftp_root: TFTP_ROOT '=' DIRECT {strncpy(tftp_root, $3, sizeof(tftp_root));}
	;

timeout: TMOUT '=' NUMBER {b_opt.timeout = $3;}
	;

prompt:	PROMPT '=' PHRASE {strncpy(b_opt.prompt, $3, sizeof(b_opt.prompt));}
	| PROMPT '=' WORD {strncpy(b_opt.prompt, $3, sizeof(b_opt.prompt));}
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

int pxed_config(const char *confname)
{
	int retc, i;
	const struct boot_item *btm;

	bopt = &b_opt;
	yyin = fopen(confname, "rb");
	if (unlikely(!yyin)) {
		logmsg(LERR, "Cannot open config file \"%s\": %s\n", confname,
				strerror(errno));
		return -1;
	}
	retc = yyparse();
	if (retc) {
		logmsg(LERR, "Configuration File Error: %d\n", retc);
		return -2;
	}
	fclose(yyin);
	printf("TFTP Root: %s\n", tftp_root);
	printf("Timeout: %d\n", bopt->timeout);
	printf("Prompt: %s\n", bopt->prompt);
	printf("Number boot items: %d\n", noboot);
	for (i = 0, btm = bopt->bitems; i < noboot; i++, btm++) {
		printf("Boot Item: %d:\n", i);
		printf("\tBoot Server Type: %04hX\n", btm->svrtyp);
		printf("\tClient Type: %d\n", (int)btm->clarch);
		printf("\tDescription: %s\n", btm->desc);
		printf("\tBoot File: %s\n", btm->bootfile);
	}
	return 0;
}

int yyerror(const char *s)
{
	int retv;

	retv = fprintf(stderr, "Line: %d: %s\n", lineno, yytext);
	return retv;
}
