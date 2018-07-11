
enum {
        medusa_event_in         = 0x00000001,
        medusa_event_out        = 0x00000002,
        medusa_event_pri        = 0x00000004,
        medusa_event_err        = 0x00000008,
        medusa_event_hup        = 0x00000010,
        medusa_event_nval       = 0x00000020,

        medusa_event_timeout    = 0x01000000,

#define medusa_event_in         medusa_event_in
#define medusa_event_out        medusa_event_out
#define medusa_event_pri        medusa_event_pri
#define medusa_event_err        medusa_event_err
#define medusa_event_hup        medusa_event_hup
#define medusa_event_nval       medusa_event_nval
#define medusa_event_timeout    medusa_event_timeout
};
