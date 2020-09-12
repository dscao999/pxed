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
%token <strval>	PHASE

%token	BOOT_FILE DESC TFTP_ROOT TMOUT PROMPT PHRASE
%token	TX86_64_EFI TX86_BIOS TIA64_EFI

%%

specs:	/* empty */
        | spec
	| specs spec
	;


spec:	tftp_root 
	| timeout 
	| prompt 
	| bspec  {
		fprintf(stderr, "Complete a boot line\n");
		if(file_ok(bopt->bitems[noboot].bootfile)) {
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
	| DESC '=' PHASE {strncpy(b_opt.bitems[noboot].desc, $3, MAX_PHRASE);}
	;

tftp_root: TFTP_ROOT '=' PATH {strncpy(tftp_root, $3, sizeof(tftp_root));
	                        fprintf(stderr, "TFTP ROOT, path: %s\n", tftp_root);}
	| TFTP_ROOT '=' WORD {strncpy(tftp_root, $3, sizeof(tftp_root));
				fprintf(stderr, "TFTP ROOT, word: %s\n", tftp_root);}
	;

timeout: TMOUT '=' NUMBER {b_opt.timeout = $3;
			fprintf(stderr, "Timeout set to: %d\n", $3);}
	;

prompt:	PROMPT '=' PHASE {strncpy(b_opt.prompt, $3, sizeof(b_opt.prompt));}
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
	return retv;
}

extern FILE *yyin;
extern int yyparse(void);

int pxed_config(const char *confname)
{
	int retc;

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
	return 0;
}

int yyerror(const char *s)
{
	int retv;

	retv = fprintf(stderr, "Line: %d: %s\n", lineno, yytext);
	return retv;
}
