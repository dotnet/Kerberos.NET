using System;

namespace Kerberos.NET
{
    [AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = true)]
    public sealed class KerberosIgnoreAttribute : Attribute
    {
        public KerberosIgnoreAttribute()
        { }
    }
}
