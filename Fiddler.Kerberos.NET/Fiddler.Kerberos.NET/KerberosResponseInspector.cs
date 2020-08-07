using System;

namespace Fiddler.Kerberos.NET
{
    public class KerberosResponseInspector : KerberosInspector, IResponseInspector2
    {
        public HTTPResponseHeaders headers { get; set; }

        public byte[] body { get; set; }

        public bool bDirty { get; }

        public bool bReadOnly { get; set; }

        protected override bool IsResponse => true;

        public override void Inspect(Session session)
        {
            var authz = session.ResponseHeaders["WWW-Authenticate"];

            if (!string.IsNullOrWhiteSpace(authz))
            {
                TryParseHeader(authz);
            }

            TryDetectKdcProxy(session, session.responseBodyBytes);
        }

        private void TryParseHeader(string authz)
        {
            var split = authz.Split(new[] { ' ' }, 2);

            if (split.Length == 1)
            {
                View.Warning = $"WWW-Authenticate: {split[0]}";
                return;
            }

            try
            {
                var message = Convert.FromBase64String(split[1]);

                View.ProcessMessage(message, $"WWW-Authenticate: {split[0]}");
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
