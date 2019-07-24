using System.Collections.Generic;
using System.Text;
using System.Linq;
using System;

namespace Kerberos.NET.Entities
{
    public partial class KrbTransitedEncoding
    {
        public void EncodeTransit(IEnumerable<string> realms)
        {
            if (Type == 0)
            {
                Type = TransitedEncodingType.DomainX500Compress;
            }

            switch (Type)
            {
                case TransitedEncodingType.DomainX500Compress:
                    Contents = EncodeX500Compress(realms);
                    break;
            }
        }

        private static readonly IEnumerable<string> EmptyTransit = new string[0];

        public IEnumerable<string> DecodeTransit()
        {
            if (Contents.Length <= 0)
            {
                return EmptyTransit;
            }

            switch (Type)
            {
                case TransitedEncodingType.DomainX500Compress:
                    return DecodeX500Compress();
            }

            return EmptyTransit;
        }

        private IEnumerable<string> DecodeX500Compress()
        {
            var realms = new List<string>();

            var encoded = Encoding.UTF8.GetString(Contents.Span);

            if (encoded.Contains('/'))
            {
                throw new InvalidOperationException($"X500 domain names are not supported: {encoded}");
            }

            var sections = encoded.Split(',');

            string lastSection = null;

            foreach (var quotedSection in sections)
            {
                var section = quotedSection.Replace("\"", "").Replace("..", ".");

                var sb = new StringBuilder();

                if (section.EndsWith('.'))
                {
                    sb.Append(section);

                    if (!string.IsNullOrEmpty(lastSection))
                    {
                        sb.Append(lastSection);
                    }

                    lastSection = section + lastSection;
                }
                else
                {
                    lastSection = section;

                    sb.Append(section);
                }

                realms.Add(sb.ToString());
            }

            return realms;
        }

        private static ReadOnlyMemory<byte> EncodeX500Compress(IEnumerable<string> realms)
        {
            // "EDU", "MIT.EDU", "ATHENA.MIT.EDU", "WASHINGTON.EDU", "CS.WASHINGTON.EDU"
            //
            // "EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS.".

            // Realm names in the transited field are separated by a ",".  The ",",
            // "\", trailing "."s, and leading spaces (" ") are special characters,
            // and if they are part of a realm name, they MUST be quoted in the
            // transited field by preceding them with a "\".
            // 
            // A realm name ending with a "." is interpreted as being prepended to
            // the previous realm.

            var sb = new StringBuilder();

            sb.Append('"');

            string lastRealm = null;

            for (var i = 0; i < realms.Count(); i++)
            {
                var realm = realms.ElementAt(i);

                if (realm.Contains('/'))
                {
                    throw new InvalidOperationException($"X500 domain names are not supported: {realm}");
                }

                if (!string.IsNullOrWhiteSpace(lastRealm))
                {
                    var indexOfLastRealm = realm.IndexOf(lastRealm);

                    if (indexOfLastRealm > 0)
                    {
                        var subStr = realm.Substring(0, indexOfLastRealm);

                        sb.Append(subStr);
                    }
                    else
                    {
                        sb.Append(realm);
                    }
                }
                else
                {
                    sb.Append(realm);
                }

                if (i < realms.Count() - 1)
                {
                    sb.Append(",");
                }

                lastRealm = realm;
            }

            sb.Append('"');

            if (sb[sb.Length - 2] == '.')
            {
                sb.Append(".");
            }

            return Encoding.UTF8.GetBytes(sb.ToString());
        }
    }
}
