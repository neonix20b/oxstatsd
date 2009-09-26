#include <stdio.h>
#include <string.h>
#include <base64.h>


static const char cb64[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char cd64[]="|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";

void encodeblock( unsigned char in[3], unsigned char out[4], int len ) {
    out[0] = cb64[ in[0] >> 2 ];
    out[1] = cb64[ ((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4) ];
    out[2] = (unsigned char) (len > 1 ? cb64[ ((in[1] & 0x0f) << 2) | ((in[2] & 0xc0) >> 6) ] : '=');
    out[3] = (unsigned char) (len > 2 ? cb64[ in[2] & 0x3f ] : '=');
}

void decodeblock( unsigned char in[4], unsigned char out[3] ) {
    out[ 0 ] = (unsigned char ) (in[0] << 2 | in[1] >> 4);
    out[ 1 ] = (unsigned char ) (in[1] << 4 | in[2] >> 2);
    out[ 2 ] = (unsigned char ) (((in[2] << 6) & 0xc0) | in[3]);
}

void b64_encode(const char* src, int sz, char* dst) {
	unsigned char in[3], *out = (unsigned char*)dst;
	int i, len;

	while (sz > 0) {
		len = 0;
		for (i = 0; i < 3; i++, sz--) {
			if (sz > 0) {
				len++;
				in[i] = src[i];
			} else
				in[i] = 0;
		}
		src += 3;
		if (len) {
			encodeblock(in, out, len);
			out += 4;
		}
	}
	*out = '\0';
}

void b64_decode(const char* src, int sz, char* dst, int* dst_sz) {
	unsigned char in[4], out[3], v;
	int i, len;
	int src_i = 0;
	int dst_i = 0;

	while( src_i <= sz ) {
		for( len = 0, i = 0; i < 4 && src_i <= sz; i++ ) {
			v = 0;
			while( src_i <= sz && v == 0 ) {
				v = (unsigned char) src[src_i++];
				v = (unsigned char) ((v < 43 || v > 122) ? 0 : cd64[ v - 43 ]);
				if( v ) {
					v = (unsigned char) ((v == '$') ? 0 : v - 61);
				}
			}
			if( src_i <= sz ) {
				len++;
				if( v ) {
					in[ i ] = (unsigned char) (v - 1);
				}
			} else {
				in[i] = 0;
			}
		}
		if( len ) {
			decodeblock( in, out );
			for( i = 0; i < len - 1; i++ ) {
				dst[dst_i++] = out[i];
			}
		}
	}
	*dst_sz = dst_i;
}

