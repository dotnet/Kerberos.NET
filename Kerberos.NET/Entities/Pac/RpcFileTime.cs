// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Globalization;
using Kerberos.NET.Ndr;

namespace Kerberos.NET.Entities.Pac
{
    public class RpcFileTime : INdrStruct
    {
        public uint LowDateTime { get; set; }

        public uint HighDateTime { get; set; }

        public void Marshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            buffer.WriteUInt32LittleEndian(this.LowDateTime);
            buffer.WriteUInt32LittleEndian(this.HighDateTime);
        }

        public void Unmarshal(NdrBuffer buffer)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException(nameof(buffer));
            }

            this.LowDateTime = buffer.ReadUInt32LittleEndian();
            this.HighDateTime = buffer.ReadUInt32LittleEndian();
        }

        public static implicit operator DateTimeOffset(RpcFileTime filetime)
        {
            if (filetime == null)
            {
                return DateTimeOffset.MinValue;
            }

            return Convert(filetime.LowDateTime, filetime.HighDateTime);
        }

        public static implicit operator RpcFileTime(DateTimeOffset dt)
        {
            return Convert(dt);
        }

        public override string ToString()
        {
            return ((DateTimeOffset)this).ToString(CultureInfo.CurrentCulture);
        }

        private const long TicksPerDay = 864000000000L;
        private const long DaysTo1601 = 584388;
        private const long FileTimeOffset = DaysTo1601 * TicksPerDay;

        public static DateTimeOffset Convert(uint low, uint high)
        {
            if (low != 0xff_ff_ff_ffL && high != 0x7f_ff_ff_ffL)
            {
                var fileTime = ((long)high << 32) + low;

                var universalTicks = fileTime + FileTimeOffset;

                return new DateTimeOffset(universalTicks, TimeSpan.Zero);
            }

            return DateTimeOffset.MinValue;
        }

        public static RpcFileTime Convert(DateTimeOffset filetime)
        {
            uint low = 0xff_ff_ff_ff;
            uint high = 0x7f_ff_ff_ff;

            if (filetime != DateTimeOffset.MinValue)
            {
                var offset = filetime.UtcTicks - FileTimeOffset;

                low = unchecked((uint)offset << 32);
                high = (uint)unchecked(offset >> 32);
            }

            return new RpcFileTime
            {
                LowDateTime = low,
                HighDateTime = high
            };
        }

        public static RpcFileTime ConvertWithoutMicroseconds(DateTimeOffset filetime)
        {
            uint low = 0xff_ff_ff_ff;
            uint high = 0x7f_ff_ff_ff;

            if (filetime != DateTimeOffset.MinValue)
            {
                var utcFiletime = filetime.UtcDateTime.ToFileTime();

                var time = utcFiletime - (utcFiletime % TimeSpan.TicksPerSecond);

                low = (uint)(time & 0xFFFFFFFF);
                high = (uint)(time >> 32);
            }

            return new RpcFileTime
            {
                LowDateTime = low,
                HighDateTime = high
            };
        }
    }
}