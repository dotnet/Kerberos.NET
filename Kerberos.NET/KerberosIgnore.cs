using System;
using System.Diagnostics.CodeAnalysis;

namespace Kerberos.NET
{
    [ExcludeFromCodeCoverage]
    [AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = true)]
    public sealed class KerberosIgnoreAttribute : Attribute
    {
        public KerberosIgnoreAttribute()
        { }
    }
}
