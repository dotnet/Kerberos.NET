using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Kerberos.NET.Crypto;
using Kerberos.NET.Crypto.AES;

namespace Kerberos.NET.Entities
{
    [StructLayout(LayoutKind.Sequential)]
    public abstract class ContextToken : Asn1Message
    {
        private static readonly Dictionary<EncryptionType, Func<KrbApReq, DecryptedData>> Decryptors
            = new Dictionary<EncryptionType, Func<KrbApReq, DecryptedData>>();

        static ContextToken()
        {
            RegisterDecryptor(EncryptionType.RC4_HMAC_NT, (token) => new RC4DecryptedData(token));
            RegisterDecryptor(EncryptionType.RC4_HMAC_NT_EXP, (token) => new RC4DecryptedData(token));

            RegisterDecryptor(EncryptionType.AES128_CTS_HMAC_SHA1_96, (token) => new AES128DecryptedData(token));
            RegisterDecryptor(EncryptionType.AES256_CTS_HMAC_SHA1_96, (token) => new AES256DecryptedData(token));
        }

        protected ContextToken(Asn1Element sequence)
        {
            for (var i = 0; i < sequence.Count; i++)
            {
                var element = sequence[i];

                switch (element.Class)
                {
                    case TagClass.Universal:
                        ParseUniversal(element);
                        break;
                    case TagClass.ContextSpecific:
                        ParseContextSpecific(element);
                        break;
                    case TagClass.Application:
                        ParseApplication(element);
                        break;
                }
            }
        }

        public MechType MechType;

        private static readonly Dictionary<string, Func<Asn1Element, ContextToken>> KnownMessageTypes
            = new Dictionary<string, Func<Asn1Element, ContextToken>>
            {
                { MechType.SPNEGO, e => new NegotiateContextToken(e, MechType.SPNEGO) },
                { MechType.NEGOEX, e => new NegotiateContextToken(e, MechType.NEGOEX) },
                { MechType.KerberosV5, e => new KerberosContextToken(e) },
                { MechType.KerberosV5Legacy, e => new KerberosContextToken(e) },
                { MechType.NTLM, e => new NegotiateContextToken(e, MechType.NTLM) }
            };

        public static void RegisterDecryptor(EncryptionType type, Func<KrbApReq, DecryptedData> func)
        {
            Decryptors[type] = func;
        }

        public abstract DecryptedData Decrypt(KeyTable keys);

        protected static DecryptedData Decrypt(KrbApReq token, KeyTable keytab)
        {
            if (token?.Ticket?.EncPart == null)
            {
                return null;
            }

            DecryptedData decryptor = null;

            if (Decryptors.TryGetValue(token.Ticket.EncPart.EType, out Func<KrbApReq, DecryptedData> func) && func != null)
            {
                decryptor = func(token);
            }

            if (decryptor != null)
            {
                decryptor.Decrypt(keytab);
            }

            return decryptor;
        }

        internal static ContextToken Parse(Asn1Element element)
        {
            string mechType = TryDiscoverMechType(element);

            if (string.IsNullOrWhiteSpace(mechType))
            {
                throw new UnknownMechTypeException();
            }

            if (!KnownMessageTypes.TryGetValue(mechType, out Func<Asn1Element, ContextToken> tokenFunc))
            {
                throw new UnknownMechTypeException(mechType);
            }

            return tokenFunc(element);
        }

        private static string TryDiscoverNtlm(byte[] rawData)
        {
            var ntlmSig = new byte[NtlmNegotiate.MessageSignature.Length];

            if (rawData.Length < ntlmSig.Length)
            {
                return null;
            }

            Buffer.BlockCopy(rawData, 0, ntlmSig, 0, ntlmSig.Length);

            if (!NtlmNegotiate.MessageSignature.SequenceEqual(ntlmSig))
            {
                return null;
            }

            return MechType.NTLM;
        }

        private static string TryDiscoverMechType(Asn1Element element)
        {
            var mechType = element.Find(e => e.Class == TagClass.Universal && e.UniversalTag == MechType.UniversalTag);

            var mechTypeStr = mechType?.AsString();

            if (string.IsNullOrWhiteSpace(mechTypeStr))
            {
                mechTypeStr = TryDiscoverNtlm(element.RawData);
            }

            return mechTypeStr;
        }

        protected virtual void ParseUniversal(Asn1Element element)
        {
            switch (element.UniversalTag)
            {
                case MechType.UniversalTag:
                    MechType = new MechType(element.AsString());
                    break;
            }
        }

        protected virtual void ParseApplication(Asn1Element element)
        {

        }

        protected virtual void ParseContextSpecific(Asn1Element element)
        {

        }
    }
}
