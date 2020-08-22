// -----------------------------------------------------------------------
// Licensed to The .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// -----------------------------------------------------------------------

using System.Linq;

namespace Kerberos.NET.Entities
{
    internal static class EntityHashCode
    {
        /// <summary>
        /// Generate a reasonably distributed hashcode for a collection of fields
        /// </summary>
        /// <param name="fields">The fields of an object</param>
        /// <returns>Returns a hashcode to be used within a GetHashCode() implementation</returns>
        public static int GetHashCode(params object[] fields)
        {
            unchecked
            {
                int hash = (int)2166136261;

                foreach (var field in fields.Where(f => f != null))
                {
                    hash = (hash * 16777619) ^ field.GetHashCode();
                }

                return hash;
            }
        }
    }
}