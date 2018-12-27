using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System.IO;

namespace Kerberos.NET
{
    public static class MessageParser
    {
        public static ContextToken ParseContext(byte[] data)
        {
            return Parse<ContextToken>(data);
        }

        public static NegotiateContextToken ParseNegotiate(byte[] data)
        {
            return Parse<NegotiateContextToken>(data);
        }

        public static KerberosContextToken ParseKerberos(byte[] data)
        {
            return Parse<KerberosContextToken>(data);
        }

        public static T Parse<T>(byte[] data)
        {
            return (T)Parse(data);
        }

        public static object Parse(byte[] data)
        {
            var element = new Asn1Element(data);

            switch (element.Class)
            {
                case TagClass.Application:
                    return ParseApplicationMessage(element);

                case TagClass.ContextSpecific:
                    return ParseContextMessage(element);

                case TagClass.Universal:
                default:
                    throw new InvalidDataException();
            }
        }

        private static object ParseContextMessage(Asn1Element element)
        {
            switch (element.ContextSpecificTag)
            {
                case 1:
                    return new NegTokenTarg().Decode(element[0]);
            }

            throw new InvalidDataException();
        }

        private static Asn1Message ParseApplicationMessage(Asn1Element element)
        {
            switch (element.ApplicationTag)
            {
                case 0: // SPNEGO InitialContextToken
                    return ContextToken.Parse(element);
            }

            throw new InvalidDataException();
        }
    }
}
