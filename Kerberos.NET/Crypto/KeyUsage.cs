// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

namespace Kerberos.NET.Crypto
{
    public enum KeyUsage
    {
        Unknown = 0,
        PaEncTs = 1,
        Ticket = 2,
        EncAsRepPart = 3,
        TgsReqAuthDataSessionKey = 4,
        TgsReqAuthDataSubSessionKey = 5,
        PaTgsReqChecksum = 6,
        PaTgsReqAuthenticator = 7,
        EncTgsRepPartSessionKey = 8,
        EncTgsRepPartSubSessionKey = 9,
        AuthenticatorChecksum = 10,
        ApReqAuthenticator = 11,
        EncApRepPart = 12,
        EncKrbPrivPart = 13,
        EncKrbCredPart = 14,
        KrbSafeChecksum = 15,
        OtherEncrypted = 16,
        PaForUserChecksum = 17,
        KrbError = 18,
        AdKdcIssuedChecksum = 19,

        MandatoryTicketExtension = 20,
        AuthDataTicketExtension = 21,
        Seal = 22,
        Sign = 23,
        Sequence = 24,
        AcceptorSeal = 22,
        AcceptorSign = 23,
        InitiatorSeal = 24,
        InitiatorSign = 25,
        PaServerReferralData = 22,
        SamChecksum = 25,
        SamEncTrackId = 26,
        PaServerReferral = 26,
        SamEncNonceSad = 27,
        PaPkInitEx = 44,
        AsReq = 56,
        FastReqChecksum = 50,
        FastEnc = 51,
        FastRep = 52,
        FastFinished = 53,
        EncChallengeClient = 54,
        EncChallengeKdc = 55,


        DigestEncrypt = -18,
        DigestOpaque = -19,
        Krb5SignedPath = -21,
        CanonicalizedPath = -23,
        HslCookie = -25
    }
}
