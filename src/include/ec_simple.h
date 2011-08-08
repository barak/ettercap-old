
#if !defined(EC_SIMPLE_H)
#define EC_SIMPLE_H


#ifdef PERMIT_PLUGINS
	extern void Simple_Plugin(void);
#endif
extern void Simple_HostList(void);
extern void Simple_Run(void);
extern void Simple_CheckForPoisoner(void);
extern void Simple_FingerPrint(void);
extern void Simple_CheckForSwitch(void);
extern void Simple_CreateCertFile(void);
extern void Simple_PassiveScan(void);

#endif

/* EOF */
