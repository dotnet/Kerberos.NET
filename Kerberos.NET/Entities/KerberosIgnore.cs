using System;

namespace Kerberos.NET.Entities
{
    [System.AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = true)]
    public sealed class KerberosIgnoreAttribute : Attribute
    {
        public KerberosIgnoreAttribute()
        { }
    }
}
