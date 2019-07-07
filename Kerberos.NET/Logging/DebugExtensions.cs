using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace Kerberos.NET.Logging
{
    public static class DebugExtensions
    {
        public static unsafe string DumpHex(this IntPtr pThing, uint length)
        {
            var pBytes = (byte*)pThing;

            return HexDump(pBytes, length);
        }

        public static unsafe string HexDump(byte* bytes, uint length, int bytesPerLine = 16)
        {
            var managedBytes = new byte[length];

            Marshal.Copy((IntPtr)bytes, managedBytes, 0, (int)length);

            return HexDump(managedBytes, bytesPerLine);
        }

        public static string HexDump(this byte[] bytes, int bytesPerLine = 16)
        {
            var sb = new StringBuilder();

            for (int line = 0; line < bytes.Length; line += bytesPerLine)
            {
                var lineBytes = bytes.Skip(line).Take(bytesPerLine).ToArray();

                sb.AppendFormat("{0:x8} ", line);

                sb.Append(string.Join(" ", lineBytes.Select(b => b.ToString("x2")).ToArray()).PadRight((bytesPerLine * 3)));

                sb.Append(" ");

                sb.Append(new string(lineBytes.Select(b => b < 32 ? '.' : (char)b).ToArray()));
                sb.AppendLine();
            }

            return sb.ToString();
        }
    }
}
