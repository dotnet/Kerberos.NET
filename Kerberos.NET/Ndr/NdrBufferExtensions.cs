using System;

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

            if (low != 0xffffffffL && high != 0x7fffffffL)
            {
                var fileTime = ((long)high << 32) + low;

                var universalTicks = fileTime + FileTimeOffset;

                return new DateTimeOffset(universalTicks, TimeSpan.Zero);
            }

            return DateTimeOffset.MinValue;
        }

        public static void WriteFiletime(this NdrBuffer buffer, DateTimeOffset filetime)
        {
            var ticks = filetime.UtcTicks - FileTimeOffset;

            var low = ticks & 0xFFFFFFFF;
            var high = ticks >> 32;

            buffer.WriteInt32LittleEndian((int)low);
            buffer.WriteInt32LittleEndian((int)high);
        }
    }
}
