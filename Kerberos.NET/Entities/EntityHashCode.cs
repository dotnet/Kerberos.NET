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

                foreach (var field in fields)
                {
                    hash = (hash * 16777619) ^ field.GetHashCode();
                }

                return hash;
            }
        }
    }
}
