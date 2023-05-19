// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Globalization;
using static System.FormattableString;

namespace Kerberos.NET.Configuration
{
    /// <summary>
    /// A parser that converts the linux duration form into TimeSpan and back.
    /// </summary>
    public static class TimeSpanDurationSerializer
    {
        private enum TimeComponent
        {
            Year,
            Day,
            Hour,
            Minute,
            Second
        }

        private static readonly Dictionary<TimeComponent, string[]> TimeSuffixes = new()
        {
            { TimeComponent.Year, new[] { "y", "yr", "year", "years" } },
            { TimeComponent.Day, new[] { "d", "day", "days" } },
            { TimeComponent.Hour, new[] { "h", "hr", "hrs", "hour", "hours" } },
            { TimeComponent.Minute, new[] { "m", "min", "minute", "minutes" } },
            { TimeComponent.Second, new[] { "s", "sec", "second", "seconds" } },
        };

        public static string ToString(TimeSpan ts)
        {
            if (ts <= TimeSpan.Zero)
            {
                return "0s";
            }

            var fields = new List<string>();

            if (ts.Days > 0)
            {
                fields.Add(Invariant($"{ts.Days}d"));
            }

            if (ts.Hours > 0)
            {
                fields.Add(Invariant($"{ts.Hours}h"));
            }

            if (ts.Minutes > 0)
            {
                fields.Add(Invariant($"{ts.Minutes}m"));
            }

            if (ts.Seconds > 0)
            {
                fields.Add(Invariant($"{ts.Seconds}s"));
            }

            if (fields.Count == 0)
            {
                fields.Add(Invariant($"{(int)ts.TotalSeconds}s"));
            }

            return string.Join(" ", fields);
        }

        public static TimeSpan Parse(string val)
        {
            if (val is null)
            {
                throw new ArgumentNullException(nameof(val));
            }

            var components = val.ToLowerInvariant().Split(' ');

            int year = 0,
                day = 0,
                hour = 0,
                minute = 0,
                second = 0;

            foreach (var component in components)
            {
                int yearIndex = IndexOf(component, TimeComponent.Year),
                    dayIndex = IndexOf(component, TimeComponent.Day),
                    hourIndex = IndexOf(component, TimeComponent.Hour),
                    minuteIndex = IndexOf(component, TimeComponent.Minute),
                    secondIndex = IndexOf(component, TimeComponent.Second);

                if (yearIndex > 0)
                {
                    year = int.Parse(component.Substring(0, yearIndex), CultureInfo.InvariantCulture);
                }
                else if (dayIndex > 0)
                {
                    day = int.Parse(component.Substring(0, dayIndex), CultureInfo.InvariantCulture);
                }
                else if (hourIndex > 0)
                {
                    hour = int.Parse(component.Substring(0, hourIndex), CultureInfo.InvariantCulture);
                }
                else if (minuteIndex > 0)
                {
                    minute = int.Parse(component.Substring(0, minuteIndex), CultureInfo.InvariantCulture);
                }
                else if (secondIndex > 0)
                {
                    second = int.Parse(component.Substring(0, secondIndex), CultureInfo.InvariantCulture);
                }
                else
                {
                    second = int.Parse(component, CultureInfo.InvariantCulture);
                }
            }

            int yearInDays = year * (DateTime.IsLeapYear(DateTime.Now.Year) ? 365 : 366);

            return new TimeSpan(yearInDays + day, hour, minute, second);
        }

        private static int IndexOf(string value, TimeComponent year)
        {
            var suffixes = TimeSuffixes[year];

            foreach (var suffix in suffixes)
            {
                var index = value.IndexOf(suffix, StringComparison.OrdinalIgnoreCase);

                if (index >= 0)
                {
                    return index;
                }
            }

            return -1;
        }
    }
}
