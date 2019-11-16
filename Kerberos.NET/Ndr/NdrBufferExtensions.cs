using System;
using System.Diagnostics;

namespace Kerberos.NET.Ndr
{
    public static class NdrBufferExtensions
    {
        private const long TicksPerDay = 864000000000L;
        private const long DaysTo1601 = 584388;
        private const long FileTimeOffset = DaysTo1601 * TicksPerDay;

        public static DateTimeOffset ReadFiletime(this NdrBuffer buffer)
        {
            var low = buffer.ReadUInt32LittleEndian();
            var high = buffer.ReadUInt32LittleEndian();

            if (low != 0xff_ff_ff_ffL && high != 0x7f_ff_ff_ffL)
            {
                var fileTime = ((long)high << 32) + low;

                var universalTicks = fileTime + FileTimeOffset;

                Debug.WriteLine($"Read UT {universalTicks} {low} {high}");

                return new DateTimeOffset(universalTicks, TimeSpan.Zero);
            }

            return DateTimeOffset.MinValue;
        }

        public static void WriteFiletime(this NdrBuffer buffer, DateTimeOffset filetime)
        {
            uint low = 0xff_ff_ff_ff;
            uint high = 0x7f_ff_ff_ff;

            if (filetime != DateTimeOffset.MinValue)
            {
                var offset = filetime.UtcTicks - FileTimeOffset;

                low = unchecked((uint)offset << 32);
                high = (uint)unchecked(offset >> 32);

                //low = unchecked((uint)offset & 0x7F_FF_FF_FF);
                //high = unchecked((uint)offset >> 32);

                Debug.WriteLine($"Write UT {offset} {low} {high}");
            }

            buffer.WriteUInt32LittleEndian(low);
            buffer.WriteUInt32LittleEndian(high);
        }
    }
}
