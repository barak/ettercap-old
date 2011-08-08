
#if !defined(EC_LOGTOFILE_H)
#define EC_LOGTOFILE_H


extern void LogToFile(SNIFFED_DATA *data);
extern void LogToFile_Collect(CONNECTION *data);

extern void LogToFile_FilteredData(u_char * buf_ip);
extern char *LogToFile_DumpPass(void);
extern char *LogToFile_MakePassiveReport(char mode);

#endif

/* EOF */
