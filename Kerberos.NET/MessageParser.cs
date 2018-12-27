using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Kerberos.NET
{
    public static class MessageParser
    {
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
                    var targ = new NegTokenTarg();
                    targ.Decode(element[0]);

                    return targ;
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
