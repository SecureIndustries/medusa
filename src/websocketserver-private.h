
#if !defined(MEDUSA_WEBSOCKETSERVER_PRIVATE_H)
#define MEDUSA_WEBSOCKETSERVER_PRIVATE_H

struct medusa_websocketserver;
struct medusa_websocketserver_client;

struct medusa_websocketserver * medusa_websocketserver_create_unlocked (struct medusa_monitor *monitor, unsigned int protocol, const char *address, unsigned short port, int (*onevent) (struct medusa_websocketserver *websocketserver, unsigned int events, void *context, void *param), void *context);
struct medusa_websocketserver * medusa_websocketserver_create_with_options_unlocked (const struct medusa_websocketserver_init_options *options);

void medusa_websocketserver_destroy_unlocked (struct medusa_websocketserver *websocketserver);

unsigned int medusa_websocketserver_get_state_unlocked (const struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_buffered_unlocked (struct medusa_websocketserver *websocketserver, int buffered);
int medusa_websocketserver_get_buffered_unlocked (const struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_enabled_unlocked (struct medusa_websocketserver *websocketserver, int enabled);
int medusa_websocketserver_get_enabled_unlocked (const struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_start_unlocked (struct medusa_websocketserver *websocketserver);
int medusa_websocketserver_stop_unlocked (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_context_unlocked (struct medusa_websocketserver *websocketserver, void *context);
void * medusa_websocketserver_get_context_unlocked (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_userdata_unlocked (struct medusa_websocketserver *websocketserver, void *userdata);
void * medusa_websocketserver_get_userdata_unlocked (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_userdata_ptr_unlocked (struct medusa_websocketserver *websocketserver, void *userdata);
void * medusa_websocketserver_get_userdata_ptr_unlocked (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_userdata_int_unlocked (struct medusa_websocketserver *websocketserver, int userdara);
int medusa_websocketserver_get_userdata_int_unlocked (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_set_userdata_uint_unlocked (struct medusa_websocketserver *websocketserver, unsigned int userdata);
unsigned int medusa_websocketserver_get_userdata_uint_unlocked (struct medusa_websocketserver *websocketserver);

int medusa_websocketserver_onevent_unlocked (struct medusa_websocketserver *websocketserver, unsigned int events, void *param);
struct medusa_monitor * medusa_websocketserver_get_monitor_unlocked (struct medusa_websocketserver *websocketserver);

struct medusa_websocketserver_client * medusa_websocketserver_accept_unlocked (struct medusa_websocketserver *websocketserver, int (*onevent) (struct medusa_websocketserver_client *websocketserver_client, unsigned int events, void *context, void *param), void *context);
struct medusa_websocketserver_client * medusa_websocketserver_accept_with_options_unlocked (struct medusa_websocketserver *websocketserver, struct medusa_websocketserver_accept_options *options);
void medusa_websocketserver_client_destroy_unlocked (struct medusa_websocketserver_client *websocketserver_client);

unsigned int medusa_websocketserver_client_get_state_unlocked (const struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_enabled_unlocked (struct medusa_websocketserver_client *websocketserver_client, int enabled);
int medusa_websocketserver_client_get_enabled_unlocked (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_start_unlocked (struct medusa_websocketserver_client *websocketserver_client);
int medusa_websocketserver_client_stop_unlocked (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_context_unlocked (struct medusa_websocketserver_client *websocketserver_client, void *context);
void * medusa_websocketserver_client_get_context_unlocked (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_userdata_unlocked (struct medusa_websocketserver_client *websocketserver_client, void *userdata);
void * medusa_websocketserver_client_get_userdata_unlocked (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_userdata_ptr_unlocked (struct medusa_websocketserver_client *websocketserver_client, void *userdata);
void * medusa_websocketserver_client_get_userdata_ptr_unlocked (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_userdata_int_unlocked (struct medusa_websocketserver_client *websocketserver_client, int userdara);
int medusa_websocketserver_client_get_userdata_int_unlocked (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_set_userdata_uint_unlocked (struct medusa_websocketserver_client *websocketserver_client, unsigned int userdata);
unsigned int medusa_websocketserver_client_get_userdata_uint_unlocked (struct medusa_websocketserver_client *websocketserver_client);

int medusa_websocketserver_client_onevent_unlocked (struct medusa_websocketserver_client *websocketserver_client, unsigned int events, void *param);
struct medusa_monitor * medusa_websocketserver_client_get_monitor_unlocked (struct medusa_websocketserver_client *websocketserver_client);

#endif
