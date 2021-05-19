// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;

namespace Kerberos.NET.Configuration
{
    public class KeySaltPair : ICanParseMyself
    {
        private static readonly char[] SplitOn = new[] { ':' };

        public EncryptionType EType { get; set; }

        public KeySaltType SaltType { get; set; }

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

            this.EType = (EncryptionType)ConfigurationSectionList.ParseEnum(split[0], typeof(EncryptionType));
            this.SaltType = (KeySaltType)ConfigurationSectionList.ParseEnum(split[1], typeof(KeySaltType));
        }

        public string Serialize()
        {
            return this.ToString();
        }

        public override string ToString()
        {
            return $"{this.EType}:{this.SaltType}";
        }

        public override int GetHashCode()
        {
            return EntityHashCode.GetHashCode(this.EType, this.SaltType);
        }

        public override bool Equals(object obj)
        {
            if (obj is KeySaltPair pair)
            {
                return pair.EType == this.EType && pair.SaltType == this.SaltType;
            }

            return false;
        }
    }
}
