// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.ComponentModel;

namespace Kerberos.NET.Configuration
{
    public class FlagString<T> : ICanParseMyself
        where T : Enum, new()
    {
        public T Flags { get; set; }

        public void Parse(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            {
                return;
            }

            var values = value.Split(',');

            var flagsAsInt = (int)(object)this.Flags;

            foreach (var val in values)
            {
                var trimmed = val.Trim();

                int flag = GetFlag(trimmed.Substring(1));

                if (val[0] == '-')
                {
                    flagsAsInt &= ~flag;
                }
                else
                {
                    flagsAsInt |= flag;
                }
            }

            this.Flags = (T)(object)flagsAsInt;
        }

        private static int GetFlag(string value)
        {
            var attributeNames = Enum.GetValues(typeof(T));

            foreach (var name in attributeNames)
            {
                var descAttr = GetAttribute<DescriptionAttribute>((Enum)name);

                if (descAttr == null)
                {
                    continue;
                }

                if (string.Equals(descAttr.Description, value))
                {
                    return (int)name;
                }
            }

            return 0;
        }

        private static TAttr GetAttribute<TAttr>(Enum value) where TAttr : Attribute
        {
            var type = value.GetType();

            var memberInfo = type.GetMember(value.ToString());

            if (memberInfo.Length <= 0)
            {
                return null;
            }

            var attributes = memberInfo[0].GetCustomAttributes(typeof(TAttr), false);

            return attributes.Length > 0 ? (TAttr)attributes[0] : null;
        }

        public string Serialize()
        {
            var names = Enum.GetValues(typeof(T));
            var flags = new List<string>();

            for (var i = 0; i < names.Length; i++)
            {
                var name = (Enum)names.GetValue(i);

                if (this.Flags.HasFlag(name))
                {
                    var descAttr = GetAttribute<DescriptionAttribute>(name);

                    if (descAttr != null)
                    {
                        flags.Add(string.Format("+{0}", descAttr.Description));
                    }
                }
            }

            return string.Join(",", flags);
        }

        public override string ToString()
        {
            return this.Flags.ToString();
        }

        public override int GetHashCode()
        {
            return this.Flags.GetHashCode();
        }

        public override bool Equals(object obj)
        {
            if (obj is FlagString<T> flags)
            {
                return flags.Flags.Equals(this.Flags);
            }

            return false;
        }
    }
}
