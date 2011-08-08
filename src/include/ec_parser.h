
#if !defined(EC_PARSER_H)
#define EC_PARSER_H


extern void Parser_ParseConfFile(char *filename);
extern void Parser_ParseParameters(char *first, char *second, char *third, char *fourth);
extern int Parser_ParseOptions(int counter, char **values);
extern void Parser_LoadFilters(char *filename);
extern char * Parser_PrintFilter(DROP_FILTER *ptr, int i);
extern int match_pattern(const char *s, const char *pattern);
extern char Parser_Activated_Plugin(char *name);
extern char *Parser_StrSpacetoUnder(char *h_name);

#endif

/* EOF */
