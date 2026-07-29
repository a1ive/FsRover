/* LzhDecoder.c -- LZH / LZS decoders shared by the LZH, ARJ and UEFI readers
 *
 * C port of 7-Zip 26.02 CPP\7zip\Compress\LzhDecoder.cpp and of the method-4
 * decoder embedded in CPP\7zip\Archive\ArjHandler.cpp (both LGPL), with the
 * MSB-first bit reader of CPP\7zip\Compress\BitmDecoder.h and the canonical
 * Huffman decoder of CPP\7zip\Compress\HuffmanDecoder.h folded in.
 * Decompression only.  See LzhDecoder.h for the interface.
 */

#include "Precomp.h"
#include "LzhDecoder.h"

#define LZH_MATCH_MIN_LEN	3
#define LZH_MATCH_MAX_LEN	256
/* literals + match lengths */
#define LZH_NC			(256 + LZH_MATCH_MAX_LEN - LZH_MATCH_MIN_LEN + 1)
#define LZH_CODE_BITS		16
#define LZH_DIC_BITS_MAX	25
/* pre-tree symbols */
#define LZH_NT			(LZH_CODE_BITS + 3)
/* distance slots; also the size of the shared T/P table */
#define LZH_NP			(LZH_DIC_BITS_MAX + 1)
#define LZH_NPT			LZH_NP

#define LZH_NUM_C_BITS		9

/* ---------------- canonical Huffman decoder ---------------- */

typedef struct
{
  /* limits[n] = first LZH_CODE_BITS-normalized value beyond length n */
  UInt32 limits[LZH_CODE_BITS + 1];
  /* poses[n] = number of symbols whose code is shorter than n */
  UInt32 poses[LZH_CODE_BITS + 1];
  /* symbols in canonical order, i.e. sorted by (length, symbol) */
  UInt16 symbols[LZH_NC];
} CLzhHuff;

/*
 * Build a complete (k_BuildMode_Full) code out of `num` code lengths.
 * Returns 1 on success.
 */
static int LzhHuff_Build(CLzhHuff *h, const Byte *lens, unsigned num)
{
  unsigned counts[LZH_CODE_BITS + 1];
  unsigned offsets[LZH_CODE_BITS + 1];
  UInt32 start;
  unsigned i, n, sum;

  for (n = 0; n <= LZH_CODE_BITS; n++)
    counts[n] = 0;
  for (i = 0; i < num; i++)
  {
    if (lens[i] > LZH_CODE_BITS)
      return 0;
    counts[lens[i]]++;
  }

  start = 0;
  sum = 0;
  h->limits[0] = 0;
  for (n = 1; n <= LZH_CODE_BITS; n++)
  {
    h->poses[n] = sum;
    offsets[n] = sum;
    sum += counts[n];
    start += (UInt32)counts[n] << (LZH_CODE_BITS - n);
    if (start > ((UInt32)1 << LZH_CODE_BITS))
      return 0;
    h->limits[n] = start;
  }
  if (start != ((UInt32)1 << LZH_CODE_BITS))
    return 0;

  for (i = 0; i < num; i++)
  {
    const unsigned len = lens[i];
    if (len != 0)
      h->symbols[offsets[len]++] = (UInt16)i;
  }
  return 1;
}

/* `v` holds the next LZH_CODE_BITS bits, MSB first; -1 on a bad code */
static int LzhHuff_Decode(const CLzhHuff *h, UInt32 v, unsigned *numbits)
{
  unsigned n;

  for (n = 1; n <= LZH_CODE_BITS; n++)
    if (v < h->limits[n])
    {
      *numbits = n;
      return h->symbols[h->poses[n]
          + ((v - h->limits[n - 1]) >> (LZH_CODE_BITS - n))];
    }
  return -1;
}

/* ---------------- MSB-first bit reader over a memory block ---------------- */

typedef struct
{
  const Byte *buf;
  SizeT size;
  SizeT pos;
  UInt32 extra;		/* 0xFF bytes fabricated past the end */
  unsigned bitPos;	/* free high bits in value */
  UInt32 value;
} CLzhBitIn;

static Byte LzhBitIn_ReadByte(CLzhBitIn *b)
{
  if (b->pos < b->size)
    return b->buf[b->pos++];
  b->extra++;
  return 0xFF;
}

static void LzhBitIn_Normalize(CLzhBitIn *b)
{
  for (; b->bitPos >= 8; b->bitPos -= 8)
    b->value = (b->value << 8) | LzhBitIn_ReadByte(b);
}

static void LzhBitIn_Init(CLzhBitIn *b, const Byte *buf, SizeT size)
{
  b->buf = buf;
  b->size = size;
  b->pos = 0;
  b->extra = 0;
  b->bitPos = 32;
  b->value = 0;
  LzhBitIn_Normalize(b);
}

/* numBits <= 24 */
static UInt32 LzhBitIn_GetValue(const CLzhBitIn *b, unsigned numBits)
{
  return ((b->value >> (8 - b->bitPos)) & 0xFFFFFF) >> (24 - numBits);
}

static void LzhBitIn_MovePos(CLzhBitIn *b, unsigned numBits)
{
  b->bitPos += numBits;
  LzhBitIn_Normalize(b);
}

static UInt32 LzhBitIn_ReadBits(CLzhBitIn *b, unsigned numBits)
{
  const UInt32 res = LzhBitIn_GetValue(b, numBits);
  LzhBitIn_MovePos(b, numBits);
  return res;
}

static UInt32 LzhBitIn_ReadAlignBits(CLzhBitIn *b)
{
  return LzhBitIn_ReadBits(b, (32 - b->bitPos) & 7);
}

static int LzhBitIn_ExtraWereRead(const CLzhBitIn *b)
{
  return (b->extra > 4 || 32 - b->bitPos < (b->extra << 3));
}

/* CDecoder::GetProcessedSize() minus the bits still sitting in `value` */
static SizeT LzhBitIn_Processed(const CLzhBitIn *b)
{
  return b->pos + b->extra - ((32 - b->bitPos) >> 3);
}

/* ---------------- shared flat output window ---------------- */

typedef struct
{
  Byte *buf;
  SizeT size;
  SizeT pos;
} CLzhOut;

/* CLzOutWindow::CopyBlock(): the real back distance is dist + 1 */
static int LzhOut_CopyBlock(CLzhOut *w, UInt32 dist, SizeT len)
{
  Byte *dest;
  const Byte *src;
  SizeT i;

  if ((SizeT)dist >= w->pos || len > w->size - w->pos)
    return 0;
  dest = w->buf + w->pos;
  src = dest - (SizeT)dist - 1;
  for (i = 0; i < len; i++)
    dest[i] = src[i];
  w->pos += len;
  return 1;
}

/* ---------------- LZH ---------------- */

typedef struct
{
  CLzhBitIn in;
  CLzhHuff dt;		/* pre-tree, then the distance table */
  CLzhHuff dc;		/* literal / length table */
  int symT;		/* >= 0 when the table degenerates to one code */
  int symC;
  UInt32 dictSize;
  CLzhOut out;
} CLzhDec;

/* CCoder::ReadTP */
static int Lzh_ReadTP(CLzhDec *d, unsigned num, unsigned numBits, int spec)
{
  Byte lens[LZH_NPT];
  unsigned n, i;

  d->symT = -1;

  n = (unsigned)LzhBitIn_ReadBits(&d->in, numBits);
  if (n == 0)
  {
    const unsigned s = (unsigned)LzhBitIn_ReadBits(&d->in, numBits);
    d->symT = (int)s;
    return s < num;
  }
  if (n > num)
    return 0;

  for (i = 0; i < LZH_NPT; i++)
    lens[i] = 0;
  i = 0;
  do
  {
    UInt32 val = LzhBitIn_GetValue(&d->in, 16);
    unsigned c = (unsigned)(val >> 13);
    unsigned mov = 3;

    if (c == 7)
    {
      while (val & (1 << 12))
      {
        val += val;
        c++;
      }
      if (c > 16)
        return 0;
      mov = c - 3;
    }
    lens[i++] = (Byte)c;
    LzhBitIn_MovePos(&d->in, mov);
    if ((int)i == spec)
      i += (unsigned)LzhBitIn_ReadBits(&d->in, 2);
  }
  while (i < n);

  return LzhHuff_Build(&d->dt, lens, LZH_NPT);
}

/* CCoder::ReadC */
static int Lzh_ReadC(CLzhDec *d)
{
  Byte lens[LZH_NC];
  unsigned n, i;

  d->symC = -1;

  n = (unsigned)LzhBitIn_ReadBits(&d->in, LZH_NUM_C_BITS);
  if (n == 0)
  {
    const unsigned s = (unsigned)LzhBitIn_ReadBits(&d->in, LZH_NUM_C_BITS);
    d->symC = (int)s;
    return s < LZH_NC;
  }
  if (n > LZH_NC)
    return 0;

  i = 0;
  do
  {
    int c = d->symT;

    if (c < 0)
    {
      unsigned nb;
      c = LzhHuff_Decode(&d->dt, LzhBitIn_GetValue(&d->in, 16), &nb);
      if (c < 0)
        return 0;
      LzhBitIn_MovePos(&d->in, nb);
    }

    if (c <= 2)
    {
      unsigned run;

      if (c == 0)
        run = 1;
      else if (c == 1)
        run = (unsigned)LzhBitIn_ReadBits(&d->in, 4) + 3;
      else
        run = (unsigned)LzhBitIn_ReadBits(&d->in, LZH_NUM_C_BITS) + 20;

      if (i + run > n)
        return 0;
      do
        lens[i++] = 0;
      while (--run);
    }
    else
    {
      if (c - 2 > LZH_CODE_BITS)
        return 0;
      lens[i++] = (Byte)(c - 2);
    }
  }
  while (i < n);

  while (i < LZH_NC)
    lens[i++] = 0;
  return LzhHuff_Build(&d->dc, lens, LZH_NC);
}

/* CCoder::CodeReal */
static int Lzh_Code(CLzhDec *d)
{
  SizeT rem = d->out.size;
  UInt32 blockSize = 0;

  while (rem != 0)
  {
    int number;
    unsigned nb;

    if (blockSize == 0)
    {
      unsigned pbit;

      if (LzhBitIn_ExtraWereRead(&d->in))
        return LZH_ERR_DATA;

      blockSize = LzhBitIn_ReadBits(&d->in, 16);
      if (blockSize == 0)
        return LZH_ERR_DATA;

      if (!Lzh_ReadTP(d, LZH_NT, 5, 3))
        return LZH_ERR_DATA;
      if (!Lzh_ReadC(d))
        return LZH_ERR_DATA;
      pbit = (d->dictSize <= LZH_DICT_EFI11) ? 4 : 5;
      if (!Lzh_ReadTP(d, LZH_NP, pbit, -1))
        return LZH_ERR_DATA;
    }

    blockSize--;

    number = d->symC;
    if (number < 0)
    {
      number = LzhHuff_Decode(&d->dc, LzhBitIn_GetValue(&d->in, 16), &nb);
      if (number < 0)
        return LZH_ERR_DATA;
      LzhBitIn_MovePos(&d->in, nb);
    }

    if (number < 256)
    {
      d->out.buf[d->out.pos++] = (Byte)number;
      rem--;
    }
    else
    {
      const SizeT len = (SizeT)number - 256 + LZH_MATCH_MIN_LEN;
      UInt32 dist;
      int slot = d->symT;

      if (slot < 0)
      {
        slot = LzhHuff_Decode(&d->dt, LzhBitIn_GetValue(&d->in, 16), &nb);
        if (slot < 0)
          return LZH_ERR_DATA;
        LzhBitIn_MovePos(&d->in, nb);
      }
      if (slot >= LZH_NP)
        return LZH_ERR_DATA;

      dist = (UInt32)slot;
      if (dist > 1)
      {
        dist--;
        dist = ((UInt32)1 << dist) + LzhBitIn_ReadBits(&d->in, dist);
      }

      if (dist >= d->dictSize)
        return LZH_ERR_DATA;
      if (len > rem)
        return LZH_ERR_DATA;
      if (!LzhOut_CopyBlock(&d->out, dist, len))
        return LZH_ERR_DATA;
      rem -= len;
    }
  }

  if (blockSize != 0)
    return LZH_ERR_DATA;
  if (LzhBitIn_ReadAlignBits(&d->in) != 0)
    return LZH_ERR_DATA;
  if (LzhBitIn_ExtraWereRead(&d->in))
    return LZH_ERR_DATA;
  return LZH_OK;
}

int LzhDecode(const Byte *in, SizeT inSize, Byte *out, SizeT outSize,
    UInt32 dictSize, SizeT *inProcessed)
{
  CLzhDec d;
  int res;

  LzhBitIn_Init(&d.in, in, inSize);
  d.symT = -1;
  d.symC = -1;
  d.dictSize = dictSize;
  d.out.buf = out;
  d.out.size = outSize;
  d.out.pos = 0;

  res = Lzh_Code(&d);
  if (inProcessed)
    *inProcessed = LzhBitIn_Processed(&d.in);
  return res;
}

/* ---------------- ARJ method 4 ---------------- */

int ArjDecode(const Byte *in, SizeT inSize, Byte *out, SizeT outSize,
    SizeT *inProcessed)
{
  CLzhBitIn b;
  CLzhOut w;
  SizeT rem = outSize;
  int res = LZH_OK;

  LzhBitIn_Init(&b, in, inSize);
  w.buf = out;
  w.size = outSize;
  w.pos = 0;

  while (rem != 0)
  {
    SizeT len;
    {
      const unsigned kNumBits = 7 + 7;
      const UInt32 val = LzhBitIn_GetValue(&b, kNumBits);
      unsigned w2, readBits;
      UInt32 mask, flag;

      if ((val & ((UInt32)1 << (kNumBits - 1))) == 0)
      {
        w.buf[w.pos++] = (Byte)(val >> 5);
        LzhBitIn_MovePos(&b, 1 + 8);
        rem--;
        continue;
      }

      flag = (UInt32)1 << (kNumBits - 2);
      for (w2 = 1; w2 < 7; w2++, flag >>= 1)
        if ((val & flag) == 0)
          break;
      readBits = (w2 != 7 ? 1 : 0) + w2 * 2;
      mask = ((UInt32)1 << w2) - 1;
      len = (SizeT)mask + LZH_MATCH_MIN_LEN - 1
          + ((val >> (kNumBits - readBits)) & mask);
      LzhBitIn_MovePos(&b, readBits);
    }
    {
      const unsigned kNumBits = 4 + 13;
      const UInt32 val = LzhBitIn_GetValue(&b, kNumBits);
      unsigned readBits = 1;
      unsigned w2;
      UInt32 dist;

           if ((val & ((UInt32)1 << 16)) == 0) w2 = 9;
      else if ((val & ((UInt32)1 << 15)) == 0) w2 = 10;
      else if ((val & ((UInt32)1 << 14)) == 0) w2 = 11;
      else if ((val & ((UInt32)1 << 13)) == 0) w2 = 12;
      else { w2 = 13; readBits = 0; }

      readBits += w2 + w2 - 9;
      dist = ((UInt32)1 << w2) - (1 << 9)
          + ((val >> (kNumBits - readBits)) & (((UInt32)1 << w2) - 1));
      LzhBitIn_MovePos(&b, readBits);

      if (len > rem)
      {
        res = LZH_ERR_DATA;
        goto done;
      }
      if (!LzhOut_CopyBlock(&w, dist, len))
      {
        res = LZH_ERR_DATA;
        goto done;
      }
      rem -= len;
    }
  }

  if (LzhBitIn_ReadAlignBits(&b) != 0)
    res = LZH_ERR_DATA;
  else if (LzhBitIn_ExtraWereRead(&b))
    res = LZH_ERR_DATA;

done:
  if (inProcessed)
    *inProcessed = LzhBitIn_Processed(&b);
  return res;
}
