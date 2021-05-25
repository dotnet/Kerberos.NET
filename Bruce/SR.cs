// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Globalization;
using System.Linq;
using Kerberos.NET.Entities;

namespace Kerberos.NET.CommandLine
{
    internal static class SR
    {
        public static string Resource(string name, params object[] args)
        {
            var resource = Strings.ResourceManager.GetString(name, CultureInfo.CurrentCulture);

            if (string.IsNullOrWhiteSpace(resource))
            {
                resource = name;
            }

            if (resource.IndexOf("{0}", StringComparison.InvariantCultureIgnoreCase) < 0 && args.Length > 0)
            {
                resource += " " + string.Join(", ", Enumerable.Range(0, args.Length).Select(i => $"{{{i}}}"));
            }

            return string.Format(CultureInfo.CurrentCulture, resource, args);
        }

        public static string ETextWithoutCode(this KrbError error)
        {
            return error?.EText?.Replace(error?.ErrorCode.ToString() + ": ", "");
        }
    }
}
