// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace Kerberos.NET.Configuration
{
    public static class DateTimeAbsoluteSerializer
    {
        private const DateTimeStyles Styles = DateTimeStyles.None;

        private static readonly IReadOnlyCollection<string> AbsoluteTimeFormats = new List<string>
        {
            "yyyyMMddHHmmss",
            "yyyy.MM.dd.HH.mm.ss",
            "yyMMddHHmmss",
            "yy.MM.dd.HH.mm.ss",
            "dd-MM-yyyy:HH:mm:ss",
            "dd-MMM-yyyy:HH:mm:ss",
            "HH:mm:ss",
            "HHmmss"
        };

        public static DateTimeOffset Parse(string stringValue)
        {
            foreach (var format in AbsoluteTimeFormats)
            {
                if (DateTime.TryParseExact(stringValue, format, CultureInfo.InvariantCulture, Styles, out DateTime result))
                {
                    return new DateTimeOffset(result, TimeSpan.Zero);
                }
            }

            throw new FormatException("Unknown absolute time format");
        }

        internal static object ToString(DateTimeOffset dt)
        {
            return dt.ToString(AbsoluteTimeFormats.First(), CultureInfo.InvariantCulture);
        }
    }
}
