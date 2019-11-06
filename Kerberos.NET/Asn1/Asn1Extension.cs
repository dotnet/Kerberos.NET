using System;
using System.Runtime.CompilerServices;

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
    }
}
