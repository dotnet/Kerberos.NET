using Syfuhs.Security.Kerberos.Entities;

namespace Syfuhs.Security.Kerberos
{
    public interface IKerberosValidator
    {
        ValidationAction ValidateAfterDecrypt { get; set; }

        DecryptedData Validate(byte[] requestBytes);
    }
}