
#if !defined(MEDUSA_SHA1_H)
#define MEDUSA_SHA1_H

#define MEDUSA_SHA1_LENGTH      20

struct medusa_sha1_context {
        uint32_t state[5];
        uint32_t count[2];
        uint8_t buffer[64];
};

#ifdef __cplusplus
extern "C"
{
#endif

void medusa_sha1_init (struct medusa_sha1_context *context);
void medusa_sha1_update (struct medusa_sha1_context *context, const uint8_t *data, uint32_t len);
void medusa_sha1_final (unsigned char digest[MEDUSA_SHA1_LENGTH], struct medusa_sha1_context *context);
void medusa_sha1 (char hash_out[MEDUSA_SHA1_LENGTH], const char *str, int len);

#ifdef __cplusplus
}
#endif

#endif
