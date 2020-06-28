
#include <string.h>
#include "base64.h"

static const unsigned char decode_table[256] =
{
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
        64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
        64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
        64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

__attribute__ ((visibility ("default"))) int medusa_base64_decode_length (const char *encoded)
{
        int nbytes;
        int ndecoded;
        const unsigned char *in;

        in = (const unsigned char *) encoded;
        while (decode_table[*(in++)] <= 63);

        nbytes = (in - (const unsigned char *) encoded) - 1;
        ndecoded = ((nbytes + 3) / 4) * 3;

        return ndecoded + 1;
}

__attribute__ ((visibility ("default"))) int medusa_base64_decode (char *decoded, const char *encoded)
{
        int nbytes;
        int ndecoded;
        unsigned char *out;
        const unsigned char *in;

        in = (const unsigned char *) encoded;
        while (decode_table[*(in++)] <= 63);
        nbytes = (in - (const unsigned char *) encoded) - 1;
        ndecoded = ((nbytes + 3) / 4) * 3;

        out = (unsigned char *) decoded;
        in = (const unsigned char *) encoded;

        while (nbytes > 4) {
                *(out++) = (unsigned char) (decode_table[*in] << 2 | decode_table[in[1]] >> 4);
                *(out++) = (unsigned char) (decode_table[in[1]] << 4 | decode_table[in[2]] >> 2);
                *(out++) = (unsigned char) (decode_table[in[2]] << 6 | decode_table[in[3]]);
                in += 4;
                nbytes -= 4;
        }

        if (nbytes > 1) {
                *(out++) = (unsigned char) (decode_table[*in] << 2 | decode_table[in[1]] >> 4);
        }
        if (nbytes > 2) {
                *(out++) = (unsigned char) (decode_table[in[1]] << 4 | decode_table[in[2]] >> 2);
        }
        if (nbytes > 3) {
                *(out++) = (unsigned char) (decode_table[in[2]] << 6 | decode_table[in[3]]);
        }

        *(out++) = '\0';
        ndecoded -= (4 - nbytes) & 3;
        return ndecoded;
}

static const char encode_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

__attribute__ ((visibility ("default"))) int medusa_base64_encode_length (int len)
{
        return ((len + 2) / 3 * 4) + 1;
}

__attribute__ ((visibility ("default"))) int medusa_base64_encode (char *encoded, const char *in, int len)
{
        int i;
        char *p;

        p = encoded;
        for (i = 0; i < len - 2; i += 3) {
                *p++ = encode_table[(in[i] >> 2) & 0x3F];
                *p++ = encode_table[((in[i] & 0x3) << 4) | ((int) (in[i + 1] & 0xF0) >> 4)];
                *p++ = encode_table[((in[i + 1] & 0xF) << 2) | ((int) (in[i + 2] & 0xC0) >> 6)];
                *p++ = encode_table[in[i + 2] & 0x3F];
        }
        if (i < len) {
                *p++ = encode_table[(in[i] >> 2) & 0x3F];
                if (i == (len - 1)) {
                        *p++ = encode_table[((in[i] & 0x3) << 4)];
                        *p++ = '=';
                } else {
                        *p++ = encode_table[((in[i] & 0x3) << 4) | ((int) (in[i + 1] & 0xF0) >> 4)];
                        *p++ = encode_table[((in[i + 1] & 0xF) << 2)];
                }
                *p++ = '=';
        }

        *p++ = '\0';
        return p - encoded;
}
