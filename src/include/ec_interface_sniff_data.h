
#if !defined(EC_INTERFACE_SNIFF_DATA_H)
#define EC_INTERFACE_SNIFF_DATA_H


extern void Interface_Sniff_Data_Run(char *ips,
                                     int portsource,
                                     char *ipd,
                                     int portdest,
                                     char *macs,
                                     char *macd,
                                     char proto,
                                     char *type,
                                     short mode);
extern void Interface_Sniff_Data_Winch(void);
extern void Interface_Sniff_Data_Redraw(void);

#endif

/* EOF */
