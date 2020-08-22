// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Collections.Generic;

namespace Tests.Kerberos.NET.Pac.Interop
{
    internal static class RpcFormatter
    {
        internal const int KerbValidationInfo = 2;

        private static byte[] NdrFcShort(int s)
        {
            return new byte[]
            {
                (byte)(s & 0xff),
                (byte)(s >> 8)
            };
        }

        private static byte[] NdrFcLong(uint s)
        {
            return new byte[]
            {
                (byte)(s & 0xff),
                (byte)((s & 0x0000ff00) >> 8),
                (byte)((s & 0x00ff0000) >> 16),
                (byte)(s >> 24)
            };
        }

        internal static byte[] Pac = Translate(new object[]
        {
            NdrFcShort(0x0),     /* 0 */
/*  2 */
            0x12, 0x0,     /* FC_UP */
/*  4 */     NdrFcShort(0xda),     /* Offset= 218 (222) */
/*  6 */
            0x15,          /* FC_STRUCT */
            0x3,          /* 3 */
/*  8 */     NdrFcShort(0x8),     /* 8 */
/* 10 */     0x8,          /* FC_LONG */
            0x8,          /* FC_LONG */
/* 12 */     0x5c,          /* FC_PAD */
            0x5b,          /* FC_END */
/* 14 */
            0x1c,          /* FC_CVARRAY */
            0x1,          /* 1 */
/* 16 */     NdrFcShort(0x2),     /* 2 */
/* 18 */     0x17,          /* Corr desc:  field pointer, FC_USHORT */
            0x55,          /* FC_DIV_2 */
/* 20 */     NdrFcShort(0x2),     /* 2 */
/* 22 */     NdrFcShort(0x1),     /* Corr flags:  early, */
/* 24 */     0x17,          /* Corr desc:  field pointer, FC_USHORT */
            0x55,          /* FC_DIV_2 */
/* 26 */     NdrFcShort(0x0),     /* 0 */
/* 28 */     NdrFcShort(0x1),     /* Corr flags:  early, */
/* 30 */     0x5,          /* FC_WCHAR */
            0x5b,          /* FC_END */
/* 32 */
            0x1a,          /* FC_BOGUS_STRUCT */
            0x3,          /* 3 */
/* 34 */     NdrFcShort(0x10),     /* 16 */
/* 36 */     NdrFcShort(0x0),     /* 0 */
/* 38 */     NdrFcShort(0x8),     /* Offset= 8 (46) */
/* 40 */     0x6,          /* FC_SHORT */
            0x6,          /* FC_SHORT */
/* 42 */     0x40,          /* FC_STRUCTPAD4 */
            0x36,          /* FC_POINTER */
/* 44 */     0x5c,          /* FC_PAD */
            0x5b,          /* FC_END */
/* 46 */
            0x12, 0x0,     /* FC_UP */
/* 48 */     NdrFcShort(0xffde),     /* Offset= -34 (14) */
/* 50 */
            0x1d,          /* FC_SMFARRAY */
            0x0,          /* 0 */
/* 52 */     NdrFcShort(0x8),     /* 8 */
/* 54 */     0x2,          /* FC_CHAR */
            0x5b,          /* FC_END */
/* 56 */
            0x15,          /* FC_STRUCT */
            0x0,          /* 0 */
/* 58 */     NdrFcShort(0x8),     /* 8 */
/* 60 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 62 */     NdrFcShort(0xfff4),     /* Offset= -12 (50) */
/* 64 */     0x5c,          /* FC_PAD */
            0x5b,          /* FC_END */
/* 66 */
            0x1d,          /* FC_SMFARRAY */
            0x0,          /* 0 */
/* 68 */     NdrFcShort(0x10),     /* 16 */
/* 70 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 72 */     NdrFcShort(0xfff0),     /* Offset= -16 (56) */
/* 74 */     0x5c,          /* FC_PAD */
            0x5b,          /* FC_END */
/* 76 */
            0x15,          /* FC_STRUCT */
            0x0,          /* 0 */
/* 78 */     NdrFcShort(0x10),     /* 16 */
/* 80 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 82 */     NdrFcShort(0xfff0),     /* Offset= -16 (66) */
/* 84 */     0x5c,          /* FC_PAD */
            0x5b,          /* FC_END */
/* 86 */
            0x1d,          /* FC_SMFARRAY */
            0x3,          /* 3 */
/* 88 */     NdrFcShort(0x8),     /* 8 */
/* 90 */     0x8,          /* FC_LONG */
            0x5b,          /* FC_END */
/* 92 */
            0x1d,          /* FC_SMFARRAY */
            0x3,          /* 3 */
/* 94 */     NdrFcShort(0x1c),     /* 28 */
/* 96 */     0x8,          /* FC_LONG */
            0x5b,          /* FC_END */
/* 98 */
            0x21,          /* FC_BOGUS_ARRAY */
            0x3,          /* 3 */
/* 100 */     NdrFcShort(0x0),     /* 0 */
/* 102 */     0x19,          /* Corr desc:  field pointer, FC_ULONG */
            0x0,          /*  null */
/* 104 */     NdrFcShort(0x9c),     /* 156 */
/* 106 */     NdrFcShort(0x1),     /* Corr flags:  early, */
/* 108 */     NdrFcLong(0xffffffff),     /* -1 */
/* 112 */     NdrFcShort(0x0),     /* Corr flags:  */
/* 114 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 116 */     NdrFcShort(0xff92),     /* Offset= -110 (6) */
/* 118 */     0x5c,          /* FC_PAD */
            0x5b,          /* FC_END */
/* 120 */
            0x1d,          /* FC_SMFARRAY */
            0x0,          /* 0 */
/* 122 */     NdrFcShort(0x6),     /* 6 */
/* 124 */     0x1,          /* FC_BYTE */
            0x5b,          /* FC_END */
/* 126 */
            0x15,          /* FC_STRUCT */
            0x0,          /* 0 */
/* 128 */     NdrFcShort(0x6),     /* 6 */
/* 130 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 132 */     NdrFcShort(0xfff4),     /* Offset= -12 (120) */
/* 134 */     0x5c,          /* FC_PAD */
            0x5b,          /* FC_END */
/* 136 */
            0x1b,          /* FC_CARRAY */
            0x3,          /* 3 */
/* 138 */     NdrFcShort(0x4),     /* 4 */
/* 140 */     0x4,          /* Corr desc: FC_USMALL */
            0x0,          /*  null */
/* 142 */     NdrFcShort(0xfff9),     /* -7 */
/* 144 */     NdrFcShort(0x1),     /* Corr flags:  early, */
/* 146 */     0x8,          /* FC_LONG */
            0x5b,          /* FC_END */
/* 148 */
            0x17,          /* FC_CSTRUCT */
            0x3,          /* 3 */
/* 150 */     NdrFcShort(0x8),     /* 8 */
/* 152 */     NdrFcShort(0xfff0),     /* Offset= -16 (136) */
/* 154 */     0x2,          /* FC_CHAR */
            0x2,          /* FC_CHAR */
/* 156 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 158 */     NdrFcShort(0xffe0),     /* Offset= -32 (126) */
/* 160 */     0x5c,          /* FC_PAD */
            0x5b,          /* FC_END */
/* 162 */
            0x1a,          /* FC_BOGUS_STRUCT */
            0x3,          /* 3 */
/* 164 */     NdrFcShort(0x10),     /* 16 */
/* 166 */     NdrFcShort(0x0),     /* 0 */
/* 168 */     NdrFcShort(0x6),     /* Offset= 6 (174) */
/* 170 */     0x36,          /* FC_POINTER */
            0x8,          /* FC_LONG */
/* 172 */     0x40,          /* FC_STRUCTPAD4 */
            0x5b,          /* FC_END */
/* 174 */
            0x12, 0x0,     /* FC_UP */
/* 176 */     NdrFcShort(0xffe4),     /* Offset= -28 (148) */
/* 178 */
            0x21,          /* FC_BOGUS_ARRAY */
            0x3,          /* 3 */
/* 180 */     NdrFcShort(0x0),     /* 0 */
/* 182 */     0x19,          /* Corr desc:  field pointer, FC_ULONG */
            0x0,          /*  null */
/* 184 */     NdrFcShort(0x110),     /* 272 */
/* 186 */     NdrFcShort(0x1),     /* Corr flags:  early, */
/* 188 */     NdrFcLong(0xffffffff),     /* -1 */
/* 192 */     NdrFcShort(0x0),     /* Corr flags:  */
/* 194 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 196 */     NdrFcShort(0xffde),     /* Offset= -34 (162) */
/* 198 */     0x5c,          /* FC_PAD */
            0x5b,          /* FC_END */
/* 200 */
            0x21,          /* FC_BOGUS_ARRAY */
            0x3,          /* 3 */
/* 202 */     NdrFcShort(0x0),     /* 0 */
/* 204 */     0x19,          /* Corr desc:  field pointer, FC_ULONG */
            0x0,          /*  null */
/* 206 */     NdrFcShort(0x128),     /* 296 */
/* 208 */     NdrFcShort(0x1),     /* Corr flags:  early, */
/* 210 */     NdrFcLong(0xffffffff),     /* -1 */
/* 214 */     NdrFcShort(0x0),     /* Corr flags:  */
/* 216 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 218 */     NdrFcShort(0xff2c),     /* Offset= -212 (6) */
/* 220 */     0x5c,          /* FC_PAD */
            0x5b,          /* FC_END */
/* 222 */
            0x1a,          /* FC_BOGUS_STRUCT */
            0x3,          /* 3 */
/* 224 */     NdrFcShort(0x138),     /* 312 */
/* 226 */     NdrFcShort(0x0),     /* 0 */
/* 228 */     NdrFcShort(0x58),     /* Offset= 88 (316) */
/* 230 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 232 */     NdrFcShort(0xff1e),     /* Offset= -226 (6) */
/* 234 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 236 */     NdrFcShort(0xff1a),     /* Offset= -230 (6) */
/* 238 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 240 */     NdrFcShort(0xff16),     /* Offset= -234 (6) */
/* 242 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 244 */     NdrFcShort(0xff12),     /* Offset= -238 (6) */
/* 246 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 248 */     NdrFcShort(0xff0e),     /* Offset= -242 (6) */
/* 250 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 252 */     NdrFcShort(0xff0a),     /* Offset= -246 (6) */
/* 254 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 256 */     NdrFcShort(0xff20),     /* Offset= -224 (32) */
/* 258 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 260 */     NdrFcShort(0xff1c),     /* Offset= -228 (32) */
/* 262 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 264 */     NdrFcShort(0xff18),     /* Offset= -232 (32) */
/* 266 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 268 */     NdrFcShort(0xff14),     /* Offset= -236 (32) */
/* 270 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 272 */     NdrFcShort(0xff10),     /* Offset= -240 (32) */
/* 274 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 276 */     NdrFcShort(0xff0c),     /* Offset= -244 (32) */
/* 278 */     0x6,          /* FC_SHORT */
            0x6,          /* FC_SHORT */
/* 280 */     0x8,          /* FC_LONG */
            0x8,          /* FC_LONG */
/* 282 */     0x8,          /* FC_LONG */
            0x36,          /* FC_POINTER */
/* 284 */     0x8,          /* FC_LONG */
            0x4c,          /* FC_EMBEDDED_COMPLEX */
/* 286 */     0x0,          /* 0 */
            NdrFcShort(0xff2d),     /* Offset= -211 (76) */
            0x40,          /* FC_STRUCTPAD4 */
/* 290 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 292 */     NdrFcShort(0xfefc),     /* Offset= -260 (32) */
/* 294 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 296 */     NdrFcShort(0xfef8),     /* Offset= -264 (32) */
/* 298 */     0x36,          /* FC_POINTER */
            0x4c,          /* FC_EMBEDDED_COMPLEX */
/* 300 */     0x0,          /* 0 */
            NdrFcShort(0xff29),     /* Offset= -215 (86) */
            0x8,          /* FC_LONG */
/* 304 */     0x4c,          /* FC_EMBEDDED_COMPLEX */
            0x0,          /* 0 */
/* 306 */     NdrFcShort(0xff2a),     /* Offset= -214 (92) */
/* 308 */     0x8,          /* FC_LONG */
            0x40,          /* FC_STRUCTPAD4 */
/* 310 */     0x36,          /* FC_POINTER */
            0x36,          /* FC_POINTER */
/* 312 */     0x8,          /* FC_LONG */
            0x40,          /* FC_STRUCTPAD4 */
/* 314 */     0x36,          /* FC_POINTER */
            0x5b,          /* FC_END */
/* 316 */
            0x12, 0x0,     /* FC_UP */
/* 318 */     NdrFcShort(0xff24),     /* Offset= -220 (98) */
/* 320 */
            0x12, 0x0,     /* FC_UP */
/* 322 */     NdrFcShort(0xff52),     /* Offset= -174 (148) */
/* 324 */
            0x12, 0x0,     /* FC_UP */
/* 326 */     NdrFcShort(0xff6c),     /* Offset= -148 (178) */
/* 328 */
            0x12, 0x0,     /* FC_UP */
/* 330 */     NdrFcShort(0xff4a),     /* Offset= -182 (148) */
/* 332 */
            0x12, 0x0,     /* FC_UP */
/* 334 */     NdrFcShort(0xff7a),     /* Offset= -134 (200) */
/* 336 */
            0x12, 0x0,     /* FC_UP */
/* 338 */     NdrFcShort(0x34),     /* Offset= 52 (390) */
/* 340 */
            0x1b,          /* FC_CARRAY */
            0x0,          /* 0 */
/* 342 */     NdrFcShort(0x1),     /* 1 */
/* 344 */     0x19,          /* Corr desc:  field pointer, FC_ULONG */
            0x0,          /*  null */
/* 346 */     NdrFcShort(0x0),     /* 0 */
/* 348 */     NdrFcShort(0x1),     /* Corr flags:  early, */
/* 350 */     0x2,          /* FC_CHAR */
            0x5b,          /* FC_END */
/* 352 */
            0x1b,          /* FC_CARRAY */
            0x0,          /* 0 */
/* 354 */     NdrFcShort(0x1),     /* 1 */
/* 356 */     0x19,          /* Corr desc:  field pointer, FC_ULONG */
            0x0,          /*  null */
/* 358 */     NdrFcShort(0x1c),     /* 28 */
/* 360 */     NdrFcShort(0x1),     /* Corr flags:  early, */
/* 362 */     0x2,          /* FC_CHAR */
            0x5b,          /* FC_END */
/* 364 */
            0x1a,          /* FC_BOGUS_STRUCT */
            0x3,          /* 3 */
/* 366 */     NdrFcShort(0x28),     /* 40 */
/* 368 */     NdrFcShort(0x0),     /* 0 */
/* 370 */     NdrFcShort(0xc),     /* Offset= 12 (382) */
/* 372 */     0x8,          /* FC_LONG */
            0x40,          /* FC_STRUCTPAD4 */
/* 374 */     0x36,          /* FC_POINTER */
            0xd,          /* FC_ENUM16 */
/* 376 */     0x8,          /* FC_LONG */
            0x6,          /* FC_SHORT */
/* 378 */     0x3e,          /* FC_STRUCTPAD2 */
            0x8,          /* FC_LONG */
/* 380 */     0x36,          /* FC_POINTER */
            0x5b,          /* FC_END */
/* 382 */
            0x12, 0x0,     /* FC_UP */
/* 384 */     NdrFcShort(0xffd4),     /* Offset= -44 (340) */
/* 386 */
            0x12, 0x0,     /* FC_UP */
/* 388 */     NdrFcShort(0xffdc),     /* Offset= -36 (352) */
/* 390 */
            0x1a,          /* FC_BOGUS_STRUCT */
            0x3,          /* 3 */
/* 392 */     NdrFcShort(0x8),     /* 8 */
/* 394 */     NdrFcShort(0x0),     /* 0 */
/* 396 */     NdrFcShort(0x4),     /* Offset= 4 (400) */
/* 398 */     0x36,          /* FC_POINTER */
            0x5b,          /* FC_END */
/* 400 */
            0x12, 0x0,     /* FC_UP */
/* 402 */     NdrFcShort(0xffda),     /* Offset= -38 (364) */
/* 404 */
            0x12, 0x0,     /* FC_UP */
/* 406 */     NdrFcShort(0x2),     /* Offset= 2 (408) */
/* 408 */
            0x1a,          /* FC_BOGUS_STRUCT */
            0x3,          /* 3 */
/* 410 */     NdrFcShort(0x8),     /* 8 */
/* 412 */     NdrFcShort(0x0),     /* 0 */
/* 414 */     NdrFcShort(0x4),     /* Offset= 4 (418) */
/* 416 */     0x36,          /* FC_POINTER */
            0x5b,          /* FC_END */
/* 418 */
            0x12, 0x0,     /* FC_UP */
/* 420 */     NdrFcShort(0xffc8),     /* Offset= -56 (364) */

            0x0
        });

        private static byte[] Translate(object[] s)
        {
            var translated = new List<byte>();

            foreach (var obj in s)
            {
                if (obj is byte[] bytes)
                {
                    translated.AddRange(bytes);
                }
                else
                {
                    translated.Add((byte)(int)obj);
                }
            }

            return translated.ToArray();
        }
    }
}