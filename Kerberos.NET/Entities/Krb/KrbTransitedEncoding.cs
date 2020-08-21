// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Kerberos.NET.Entities
{
    public partial class KrbTransitedEncoding
    {
        public void EncodeTransit(IEnumerable<string> realms)
        {
            if (this.Type == 0)
            {
                this.Type = TransitedEncodingType.DomainX500Compress;
            }

            switch (this.Type)
            {
                case TransitedEncodingType.DomainX500Compress:
                    this.Contents = EncodeX500Compress(realms);
                    break;
            }
        }

        private static readonly IEnumerable<string> EmptyTransit = Enumerable.Empty<string>();

        public IEnumerable<string> DecodeTransit()
        {
            if (this.Contents.Length <= 0)
            {
                return EmptyTransit;
            }

            switch (this.Type)
            {
                case TransitedEncodingType.DomainX500Compress:
                    return this.DecodeX500Compress();
            }

            return EmptyTransit;
        }

        private IEnumerable<string> DecodeX500Compress()
        {
            var realms = new List<string>();
            var encoded = Encoding.UTF8.GetString(this.Contents.Span.ToArray());
            if (encoded.Contains('/'))
            {
                throw new InvalidOperationException($"X500 domain names are not supported: {encoded}");
            }

            var sections = encoded.Split(',');

            string lastSection = null;

            foreach (var quotedSection in sections)
            {
                var section = quotedSection.Replace("\"", string.Empty).Replace("..", ".");

                var sb = new StringBuilder();

                if (section.EndsWith(".", StringComparison.InvariantCultureIgnoreCase))
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
                    var indexOfLastRealm = realm.IndexOf(lastRealm, StringComparison.OrdinalIgnoreCase);

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