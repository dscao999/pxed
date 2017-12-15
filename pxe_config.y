%code top{
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include "misc.h"
#include "pxe_util.h"

#define VENDOR_TYPE 32769

static int nospec = 0;
extern pxe_config_t *pconf_g;
extern int conferr;
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
static char tftp_root[MAXPATH];
extern void yyrewind(void);
}


%token <intval> NUMBER
%token <strval>	PATH
%token <strval>	WORD
%token <strval>	PHASE

%token	BOOTFILE TYPE DESC TFROOT TMOUT PROMPT LOGFILE PORT67 YES NO
%token	EFI64 EFI32 BIOS BIOS64 IA64

%%

input:	/* empty */
	| input line
	;


line:	'\n'
	| tfroot '\n'
	| timeout '\n'
	| prompt '\n'
	| logfile '\n'
	| port67 '\n'
	| specs '\n' {
		if(file_ok(pconf_g->bootsvrs[nospec].bfile)) {
			pconf_g->bootsvrs[nospec].seq = VENDOR_TYPE + nospec;
			nospec++;
			pconf_g->svrs = nospec;
		} else {
			errlog("An Invalid File Specification: %s\n",
				pconf_g->bootsvrs[nospec].bfile);
			conferr = 1;
		}
	}
	;

specs:	spec 
	| specs spec
	;

spec:	TYPE '=' EFI64 {pconf_g->bootsvrs[nospec].type = X86_64_EFI;}
	| TYPE '=' EFI32 {pconf_g->bootsvrs[nospec].type = I386_EFI;}
	| TYPE '=' BIOS {pconf_g->bootsvrs[nospec].type = I386_BIOS;}
	| TYPE '=' BIOS64 {pconf_g->bootsvrs[nospec].type = X86_64_BIOS;}
	| TYPE '=' IA64 {pconf_g->bootsvrs[nospec].type = IA64_EFI;}
	| BOOTFILE '=' PATH {strncpy(pconf_g->bootsvrs[nospec].bfile, $3, MAXPATH);
				pconf_g->bootsvrs[nospec].blen = strlen($3);}
	| BOOTFILE '=' WORD {strncpy(pconf_g->bootsvrs[nospec].bfile, $3, MAXPATH);
				pconf_g->bootsvrs[nospec].blen = strlen($3);}
	| DESC '=' WORD {strncpy(pconf_g->bootsvrs[nospec].desc, $3, MAXSTRING);
			pconf_g->bootsvrs[nospec].dlen = strlen($3);}
	| DESC '=' PHASE {strncpy(pconf_g->bootsvrs[nospec].desc, $3, MAXSTRING);
			pconf_g->bootsvrs[nospec].dlen = strlen($3);}
	;

tfroot: TFROOT '=' PATH {strncpy(tftp_root, $3, MAXPATH);}
	| TFROOT '=' WORD {strncpy(tftp_root, $3, MAXPATH);}
	;

timeout: TMOUT '=' NUMBER {pconf_g->timeout = $3;}
	;

prompt:	PROMPT '=' PHASE {strncpy(pconf_g->prompt, $3, MAXSTRING);
			pconf_g->plen = strlen(pconf_g->prompt);}
	| PROMPT '=' WORD {strncpy(pconf_g->prompt, $3, MAXSTRING);
			pconf_g->plen = strlen(pconf_g->prompt);}
	;

logfile: LOGFILE '=' PATH {strncpy(pconf_g->logfile, $3, sizeof(pconf_g->logfile));}
	| LOGFILE '=' WORD {strncpy(pconf_g->logfile, $3, sizeof(pconf_g->logfile));}
	;

port67: PORT67 '=' YES {pconf_g->m67 = 1;}
	| PORT67 '=' NO {pconf_g->m67 = 0;}
	;

%%

static int file_ok(const char *filename)
{
	int retv, sysret, len;
	struct stat file_state;
	char fname[256];

	retv = 0;
	if (!filename || *filename == 0) goto z_exit;

	len = strlen(tftp_root);
	if (len > 0) {
		strcpy(fname, tftp_root);
		if (fname[len-1] != '/' &&
		  *filename != '/')
			strcat(fname, "/");
		strcat(fname, filename);
	} else
		strcpy(fname, filename);
	sysret = stat(fname, &file_state);
	if (sysret == -1) goto z_exit;
	if (S_ISREG(file_state.st_mode))
		retv = 1;

z_exit:
	return retv;
}

int yyerror(const char *msg)
{
        errlog("%d: %s at %s\n", yylineno, msg, yytext);
        return 0;
}
void yyrewind(void)
{
	nospec = 0;
}
