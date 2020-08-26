%{
#include "pxe_config.tab.h"
%}

%option  noyywrap
NAME	[[:alpha:][[:alnum:]\-_.]*
%%

#.*$		;
\\\n		;
[ \t]+		;
\n		{return '\n';}
=		{return '=';}
^tftp" "+root	{return TFROOT;}
^timeout	{return TMOUT;}
^prompt		{return PROMPT;}
BIOS		{return BIOS;}
BIOS64		{return BIOS64;}
EFI64		{return EFI64;}
EFI32		{return EFI32;}
IA64		{return IA64;}
(?i:bfile)    	{return BOOTFILE;}
(?i:type)	{return TYPE;}
(?i:desc)	{return DESC;}
(?i:logfile)	{return LOGFILE;}
(?i:verbose)	{return VERBOSE;}
(?i:yes)	{return YES;}
(?i:no)		{return NO;}
[0-9]+		{	yylval.intval = atoi(yytext);
			return NUMBER; }
\"[^\"]+\"		{*(yytext+yyleng-1) = 0; yylval.strval = yytext+1;
			return PHASE;}
{NAME}		{yylval.strval = yytext;
			return WORD; }
\/?{NAME}(\/{NAME})* {yylval.strval = yytext;
					return PATH;}
