
#if !defined(EC_INTERFACE_INJECT_H)
#define EC_INTERFACE_INJECT_H


extern int Interface_Inject_Run(u_char *inject_data, char proto, char *app);
extern int Interface_Inject_Filter(DROP_FILTER *filters);
extern void Interface_Inject_SetFilter(short mode);
extern void Interface_Inject_FilterTopStatus(void);
extern void Interface_Inject_FilterStatus(void);

#endif

/* EOF */
