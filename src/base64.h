
#if !defined(MEDUSA_BASE64_H)
#define MEDUSA_BASE64_H

#ifdef __cplusplus
extern "C"
{
#endif

int medusa_base64_decode_length (const char *encoded);
int medusa_base64_decode (char *decoded, const char *encoded);

int medusa_base64_encode_length (int len);
int medusa_base64_encode (char *encoded, const char *in, int len);

#ifdef __cplusplus
}
#endif

#endif
