using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Entities
{
    [StructLayout(LayoutKind.Sequential)]
    public abstract class ContextToken : Asn1Message
    {
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

        public Oid MechType;

        private static readonly Dictionary<string, Func<Asn1Element, ContextToken>> KnownMessageTypes
            = new Dictionary<string, Func<Asn1Element, ContextToken>>
            {
                { Entities.MechType.SPNEGO, e=> new NegotiateContextToken(e) },
                { Entities.MechType.NEGOEX, e=> new NegotiateContextToken(e) },
                { Entities.MechType.KerberosV5, e=> new KerberosContextToken(e) },
                { Entities.MechType.KerberosV5Legacy, e=> new KerberosContextToken(e) }
            };

        internal static ContextToken Parse(Asn1Element element)
        {
            string mechType = TryDiscoverMechType(element);

            if (string.IsNullOrWhiteSpace(mechType))
            {
                throw new InvalidDataException();
            }

            if (!KnownMessageTypes.TryGetValue(mechType, out Func<Asn1Element, ContextToken> tokenFunc))
            {
                throw new InvalidDataException();
            }

            return tokenFunc(element);
        }

        private static string TryDiscoverMechType(Asn1Element element)
        {
            var mechType = element.Find(e => e.Class == TagClass.Universal && e.UniversalTag == Entities.MechType.UniversalTag);

            return mechType?.AsString();
        }

        protected virtual void ParseUniversal(Asn1Element element)
        {
            switch (element.UniversalTag)
            {
                case Entities.MechType.UniversalTag:
                    MechType = new Oid(element.AsString());
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
