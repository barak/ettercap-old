
#if !defined(EC_INTERFACE_FORM_H)
#define EC_INTERFACE_FORM_H


extern FIELD *make_label(int frow, int fcol, char *label);
extern FIELD *make_field(int frow, int fcol, int rows, int cols, bool secure);
extern void display_form(FORM *f);
extern void erase_form(FORM *f);
extern int form_virtualize(FORM *f, WINDOW *w);
extern int my_form_driver(FORM *form, int c);
extern int get_form_data(FORM *form, WINDOW *w);
extern void trim_buffer(char *buffer, char trim);

#define CTRL(x)      ((x) & 0x1f)
#define QUIT         CTRL('Q')
#define ESCAPE       CTRL('[')
#define KEY_RETURN   10
#define KEY_INS      331

#endif

/* EOF */
