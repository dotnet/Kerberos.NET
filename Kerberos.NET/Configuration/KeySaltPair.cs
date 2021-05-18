// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;

namespace Kerberos.NET.Configuration
{
    public class KeySaltPair : ICanParseMyself
    {
        private static readonly char[] SplitOn = new[] { ':' };

        public EncryptionType Etype { get; set; }

        public SaltType SaltType { get; set; }

        public void Parse(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            var split = value.Split(SplitOn, StringSplitOptions.RemoveEmptyEntries);

            if (split.Length != 2)
            {
                return;
            }

            this.Etype = (EncryptionType)ConfigurationSectionList.ParseEnum(split[0], typeof(EncryptionType));
            this.SaltType = (SaltType)ConfigurationSectionList.ParseEnum(split[1], typeof(SaltType));
        }

        public string Serialize()
        {
            return $"{this.Etype}:{this.SaltType}";
        }
    }
}
