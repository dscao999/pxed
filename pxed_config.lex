%{
#include "pxed_config.tab.h"

int lineno = 1;
%}

%option  noyywrap
NAME	[a-zA-Z][a-zA-Z0-9_.\-]*
%%

#.*$		;
[ \t]+		;
\n		{lineno++;}
=		{return SETTO;}
tftp[ \t]+root	{return TFTP_ROOT;}
timeout		{return TMOUT;}
prompt		{return PROMPT;}
X86_BIOS	{return TX86_BIOS;}
X86_64_EFI	{return TX86_64_EFI;}
IA64_EFI	{return TIA64_EFI;}
bootfile	{return BOOT_FILE;}
desc		{return DESC;}
[0-9]+		{yylval.intval = atoi(yytext); return NUMBER;}
{NAME}		{yylval.strval = yytext; return WORD;}
\/{NAME}(\/{NAME})*\/        {yylval.strval = yytext; return DIRECT;}
\/{NAME}(\/{NAME})*        {yylval.strval = yytext; return PATH;}
\"{NAME}([ \t]+{NAME})*\" {yytext[yyleng-1] = 0; yylval.strval = yytext+1; return PHRASE;}
