using System;

namespace Kerberos.NET.Entities
{
    [AttributeUsage(AttributeTargets.All, Inherited = false, AllowMultiple = true)]
    sealed class TreatAsTagAttribute : Attribute
    {
        public TreatAsTagAttribute()
        {
        }

        public TreatAsTagAttribute(int tag, string propertyName)
        {
            Tag = tag;
            PropertyName = propertyName;
        }

        public int Tag { get; }

        public string PropertyName { get; }
    }
}