
#if !defined(EC_INTERFACE_H)
#define EC_INTERFACE_H


extern void Interface_InitTitle(char *ip, char *mac, char *subnet);
extern void Interface_InitScreen(void);
extern void Interface_CloseScreen(void);
extern void Interface_Run(void);
extern void Interface_Winch(void);
extern void Interface_WExit(char *buffer);
extern void Interface_Redraw(void);
extern char Interface_PopUp(char *question, ...);
extern void Interface_HelpWindow(char *help[]);

#endif

/* EOF */
