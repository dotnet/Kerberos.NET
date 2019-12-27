using Kerberos.NET.Crypto;
using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.Asn1;

namespace Kerberos.NET.Asn1
{
    internal static class Asn1Extension
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool HasValue<T>(T thing)
            where T : class
        {
            return thing != null;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool HasValue<T>(T? thing)
            where T : struct
        {
            return thing.HasValue;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static bool HasValue(Enum thing)
        {
            return thing != null;
        }

        internal static ReadOnlyMemory<byte> DepadLeft(this ReadOnlyMemory<byte> data)
        {
            var result = data;

            for (var i = 0; i < data.Length; i++)
            {
                if (data.Span[i] == 0)
                {
                    result = result.Slice(i + 1);
                }
                else
                {
                    break;
                }
            }

            return result;
        }

        internal static void WriteKeyParameterInteger(this AsnWriter writer, ReadOnlySpan<byte> integer)
        {
            Debug.Assert(!integer.IsEmpty);

            if (integer[0] == 0)
            {
                int newStart = 1;

                while (newStart < integer.Length)
                {
                    if (integer[newStart] >= 0x80)
                    {
                        newStart--;
                        break;
                    }

                    if (integer[newStart] != 0)
                    {
                        break;
                    }

                    newStart++;
                }

                if (newStart == integer.Length)
                {
                    newStart--;
                }

                integer = integer.Slice(newStart);
            }

            writer.WriteIntegerUnsigned(integer);
        }
    }
}
