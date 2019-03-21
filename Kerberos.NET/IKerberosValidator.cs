using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using System.Threading.Tasks;

namespace Kerberos.NET
{
    public interface IKerberosValidator
    {
        ValidationActions ValidateAfterDecrypt { get; set; }

        Task<DecryptedData> Validate(byte[] requestBytes);

        void Validate(PacElement pac, PrincipalName sname);
    }
}