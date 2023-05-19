// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System;
using System.Buffers;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Kerberos.NET.Configuration;

namespace Kerberos.NET.Reflection
{
    public static class Reflect
    {
        public static bool IsClass(Type type)
        {
            return type.IsClass &&
                   type != typeof(string) &&
                   type != typeof(Uri);
        }

        public static bool IsPrimitive(Type propertyType)
        {
            return propertyType.IsPrimitive ||
                   propertyType == typeof(string) ||
                   propertyType == typeof(TimeSpan) ||
                   propertyType == typeof(DateTimeOffset) ||
                   propertyType.BaseType == typeof(Enum);
        }

        public static bool IsDictionary(Type propertyType)
        {
            return propertyType.IsGenericType && (
                propertyType.GetGenericTypeDefinition() == typeof(IDictionary<,>) ||
                propertyType.GetGenericTypeDefinition() == typeof(Dictionary<,>) ||
                propertyType.GetGenericTypeDefinition() == typeof(ConfigurationDictionary<,>)
            );
        }

        public static bool IsEnumerable(Type propertyType)
        {
            if (!propertyType.IsGenericType || propertyType == typeof(string) || propertyType.IsArray)
            {
                return false;
            }

            var type = propertyType.GetGenericTypeDefinition();

            return typeof(IEnumerable).IsAssignableFrom(type);
        }

        public static bool IsBytes(Type type)
        {
            return type == typeof(ReadOnlyMemory<byte>) ||
                   type == typeof(Memory<byte>) ||
                   type == typeof(ReadOnlyMemory<byte>?) ||
                   type == typeof(ReadOnlySequence<byte>) ||
                   type == typeof(ReadOnlyMemory<int>) ||
                   type == typeof(byte[]);
        }

        public static bool IsBytes(object value, out ReadOnlyMemory<byte> bytes)
        {
            bytes = default;

            if (value.GetType() == typeof(ReadOnlyMemory<byte>))
            {
                bytes = (ReadOnlyMemory<byte>)value;
            }
            else if (value.GetType() == typeof(Memory<byte>))
            {
                bytes = (Memory<byte>)value;
            }
            else if (value.GetType() == typeof(ReadOnlyMemory<byte>?))
            {
                var val = (ReadOnlyMemory<byte>?)value;

                if (val != null)
                {
                    bytes = val.Value;
                }
            }
            else if (value.GetType() == typeof(ReadOnlySequence<byte>))
            {
                var val = (ReadOnlySequence<byte>)value;

                bytes = val.ToArray();
            }
            else if (value.GetType() == typeof(ReadOnlyMemory<int>))
            {
                bytes = MemoryMarshal.Cast<int, byte>(((ReadOnlyMemory<int>)value).Span).ToArray();
            }
            else if (value.GetType() == typeof(byte[]))
            {
                bytes = (byte[])value;
            }
            else
            {
                return false;
            }

            return true;
        }
    }
}
