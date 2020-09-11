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
}

%union {
	int intval;
	char *strval;
}

%code {
extern int yylineno;
extern char *yytext;
extern int yylex(void);
static int file_ok(const char *filename);
extern int yyerror(const char *s);
}


%token <intval> NUMBER
%token <strval>	PATH
%token <strval>	WORD
%token <strval>	PHASE

%token	BOOT_FILE DESC TFTP_ROOT TMOUT PROMPT PHRASE
%token	TX86_64_EFI TX86_BIOS TIA64_EFI

%%

input:	line
	| input line
	;


line:	'\n'
	| tftp_root '\n'
	| timeout '\n'
	| prompt '\n'
	| specs '\n' {
		if(file_ok(bopt->bitems[noboot].bootfile)) {
			noboot++;
		} else {
			logmsg(LERR, "An Invalid File Specification: %s\n",
				b_opt.bitems[noboot].bootfile);
			config_err = 1;
		}
	}
	;

specs:	spec 
	| specs spec
	;

spec:	TX86_64_EFI {b_opt.bitems[noboot].clarch = X86_64_EFI;}
	| TX86_BIOS {b_opt.bitems[noboot].clarch = X86_BIOS;}
	| TIA64_EFI {b_opt.bitems[noboot].clarch = IA64_EFI;}
	| BOOT_FILE '=' PATH {strncpy(b_opt.bitems[noboot].bootfile, $3, MAX_PATH);}
	| BOOT_FILE '=' WORD {strncpy(b_opt.bitems[noboot].bootfile, $3, MAX_PATH);}
	| DESC '=' WORD {strncpy(b_opt.bitems[noboot].desc, $3, MAX_PHRASE);}
	| DESC '=' PHASE {strncpy(b_opt.bitems[noboot].desc, $3, MAX_PHRASE);}
	;

tftp_root: TFTP_ROOT '=' PATH {strncpy(tftp_root, $3, sizeof(tftp_root)); fprintf(stderr, "At tftp root path\n");}
	| TFTP_ROOT '=' WORD {strncpy(tftp_root, $3, sizeof(tftp_root)); fprintf(stderr, "at tftp root word %s\n", $3);}
	;

timeout: TMOUT '=' NUMBER {b_opt.timeout = $3;}
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

int yyerror(const char *msg)
{
        logmsg(LERR, "%d: %s at %s\n", yylineno, msg, yytext);
        return 0;
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
		yyerror("WHERE? ");
		logmsg(LERR, "Configuration File Error: %d\n", retc);
		return -2;
	}
	return 0;
}
