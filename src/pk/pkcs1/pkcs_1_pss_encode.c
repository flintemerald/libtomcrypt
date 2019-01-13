/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 */
#include "tomcrypt_private.h"

/**
  @file pkcs_1_pss_encode.c
  PKCS #1 PSS Signature Padding, Tom St Denis
*/

#ifdef LTC_PKCS_1

/**
   PKCS #1 v2.00 Signature Encoding
   @param msghash          The hash to encode
   @param msghashlen       The length of the hash (octets)
   @param content_hash_idx  The index of the content hash desired
   @param saltlen          The length of the salt desired (octets)
   @param prng             An active PRNG context
   @param prng_idx         The index of the PRNG desired
   @param hash_idx         The index of the hash desired
   @param modulus_bitlen   The bit length of the RSA modulus
   @param out              [out] The destination of the encoding
   @param outlen           [in/out] The max size and resulting size of the encoded data
   @return CRYPT_OK if successful
*/
int pkcs_1_pss_encode(const unsigned char *msghash, unsigned long msghashlen, int content_hash_idx,
                            unsigned long saltlen,  prng_state   *prng,
                            int           prng_idx, int           hash_idx,
                            unsigned long modulus_bitlen,
                            unsigned char *out,     unsigned long *outlen)
{
   unsigned char *mDash;
   unsigned char *DB, *mask, *salt, *hash;
   unsigned long x, y, hLenContent, modulus_len, mDashLen;
   int           err;
   hash_state    md;

   LTC_ARGCHK(msghash != NULL);
   LTC_ARGCHK(out     != NULL);
   LTC_ARGCHK(outlen  != NULL);

   /* ensure hash and PRNG are valid */
   if ((err = hash_is_valid(hash_idx)) != CRYPT_OK) {
      return err;
   }
   if ((err = hash_is_valid(content_hash_idx)) != CRYPT_OK) {
      return err;
   }
   if ((err = prng_is_valid(prng_idx)) != CRYPT_OK) {
      return err;
   }

   hLenContent = hash_descriptor[content_hash_idx].hashsize;
   modulus_bitlen--;
   modulus_len = (modulus_bitlen>>3) + (modulus_bitlen & 7 ? 1 : 0);
   mDashLen    = 8 + saltlen + hLenContent;

   /* check sizes */
   if ((saltlen > modulus_len) || (modulus_len < hLenContent + saltlen + 2)) {
      return CRYPT_PK_INVALID_SIZE;
   }

   /* allocate ram for DB/mask/salt/hash of size modulus_len */
   mDash = XMALLOC(mDashLen);
   DB   = XMALLOC(modulus_len);
   mask = XMALLOC(modulus_len);
   salt = XMALLOC(modulus_len);
   hash = XMALLOC(modulus_len);
   if (mDash == NULL || DB == NULL || mask == NULL || salt == NULL || hash == NULL) {
      if (mDash != NULL) {
          XFREE(mDash);
      }
      if (DB != NULL) {
         XFREE(DB);
      }
      if (mask != NULL) {
         XFREE(mask);
      }
      if (salt != NULL) {
         XFREE(salt);
      }
      if (hash != NULL) {
         XFREE(hash);
      }
      return CRYPT_MEM;
   }

   zeromem(mDash, mDashLen);
   XMEMCPY(mDash+8, msghash, msghashlen);

   /* generate random salt */
   if (saltlen > 0) {
      if (prng_descriptor[prng_idx].read(salt, saltlen, prng) != saltlen) {
         err = CRYPT_ERROR_READPRNG;
         goto LBL_ERR;
      }
   }

   XMEMCPY(mDash + mDashLen - saltlen, salt, saltlen);

   if ((err = hash_descriptor[content_hash_idx].init(&md)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[content_hash_idx].process(&md, mDash, mDashLen)) != CRYPT_OK) {
      goto LBL_ERR;
   }
   if ((err = hash_descriptor[content_hash_idx].done(&md, hash)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* generate DB = PS || 0x01 || salt, PS == modulus_len - saltlen - hLen - 2 zero bytes */
   x = 0;
   XMEMSET(DB + x, 0, modulus_len - saltlen - hLenContent - 2);
   x += modulus_len - saltlen - hLenContent - 2;
   DB[x++] = 0x01;
   XMEMCPY(DB + x, salt, saltlen);
   /* x += saltlen; */

   /* generate mask of length modulus_len - hLen - 1 from hash */
   if ((err = pkcs_1_mgf1(hash_idx, hash, hLenContent, mask, modulus_len - hLenContent - 1)) != CRYPT_OK) {
      goto LBL_ERR;
   }

   /* xor against DB */
   for (y = 0; y < (modulus_len - hLenContent - 1); y++) {
      DB[y] ^= mask[y];
   }

   /* output is DB || hash || 0xBC */
   if (*outlen < modulus_len) {
      *outlen = modulus_len;
      err = CRYPT_BUFFER_OVERFLOW;
      goto LBL_ERR;
   }

   /* DB len = modulus_len - hLen - 1 */
   y = 0;
   XMEMCPY(out + y, DB, modulus_len - hLenContent - 1);
   y += modulus_len - hLenContent - 1;

   /* hash */
   XMEMCPY(out + y, hash, hLenContent);
   y += hLenContent;

   /* 0xBC */
   out[y] = 0xBC;

   /* now clear the 8*modulus_len - modulus_bitlen most significant bits */
   out[0] &= 0xFF >> ((modulus_len<<3) - modulus_bitlen);

   /* store output size */
   *outlen = modulus_len;
   err = CRYPT_OK;
LBL_ERR:
#ifdef LTC_CLEAN_STACK
   zeromem(mDash, mDashLen)
   zeromem(DB,   modulus_len);
   zeromem(mask, modulus_len);
   zeromem(salt, modulus_len);
   zeromem(hash, modulus_len);
#endif

   XFREE(hash);
   XFREE(salt);
   XFREE(mask);
   XFREE(DB);
   XFREE(mDash);

   return err;
}

#endif /* LTC_PKCS_1 */

/* ref:         $Format:%D$ */
/* git commit:  $Format:%H$ */
/* commit time: $Format:%ai$ */
