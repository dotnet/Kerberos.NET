using System;

namespace Fiddler.Kerberos.NET
{
    public class KerberosRequestInspector : KerberosInspector, IRequestInspector2
    {
        public byte[] body { get; set; }

        public bool bDirty { get; }

        public bool bReadOnly { get; set; } = true;

        protected override bool IsRequest => true;

        HTTPRequestHeaders IRequestInspector2.headers { get; set; }

        public override void Inspect(Session session)
        {
            var authz = session.RequestHeaders["Authorization"];

            if (!string.IsNullOrWhiteSpace(authz))
            {
                TryParseHeader(authz);
            }

            TryDetectKdcProxy(session, session.requestBodyBytes);
        }

        private void TryParseHeader(string authz)
        {
            var split = authz.Split(new[] { ' ' }, 2);

            if (split.Length != 2)
            {
                return;
            }

            if (!string.Equals("negotiate", split[0], StringComparison.InvariantCultureIgnoreCase) &&
                !string.Equals("kerberos", split[0], StringComparison.InvariantCultureIgnoreCase))
            {
                return;
            }

            try
            {
                var message = Convert.FromBase64String(split[1]);

                View.ProcessMessage(message, $"Authorization: {split[0]}");
            }
            catch (FormatException)
            {
                View.Warning = "Message is not formatted correctly";
            }
            catch (Exception ex)
            {
                View.Warning = ex.ToString();
            }
        }
    }
}
