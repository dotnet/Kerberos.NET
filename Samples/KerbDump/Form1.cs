using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection.Emit;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using KerbDump.Properties;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Entities.SpNego;
using Kerberos.NET.Win32;

#pragma warning disable IDE1006 // Naming Styles

namespace KerbDump
{
    public partial class DecoderForm : Form
    {
        private const string RequestTemplateText = "Request for {0}";

        private readonly ContextMenuStrip exportMenu = new();
        private CancellationTokenSource cancellation = new();

        private readonly int splitter1Default;

        private bool running = false;

        private KeyTable table;

        public DecoderForm()
        {
            this.AutoScaleDimensions = new SizeF(96F, 96F);
            this.AutoScaleMode = AutoScaleMode.Dpi;

            this.InitializeComponent();

            this.exportMenu.Items.Add("Export to WireShark", null, this.ExportWireshark);
            this.exportMenu.Items.Add("Export to Keytab", null, this.ExportKeytab);

            this.ddlKeyType.SelectedIndex = 0;
            this.ddlKeyType.DropDownStyle = ComboBoxStyle.DropDownList;

            this.btnExport.Click += (s, e) =>
            {
                this.exportMenu.Show(this.btnExport, new Point());
            };

            this.splitter1Default = this.splitContainer1.SplitterDistance;

            this.splitContainer1.DoubleClick += (s, e) =>
            {
                if (this.splitContainer1.SplitterDistance >= this.splitter1Default)
                {
                    this.splitContainer1.SplitterDistance = 5;
                }
                else
                {
                    this.splitContainer1.SplitterDistance = this.splitter1Default;
                }
            };

            this.lblDecode.Text = "";
            this.lblKeytab.Text = "";

            CryptoService.RegisterCryptographicAlgorithm(EncryptionType.NULL, () => new NoopTransform());

            CryptoService.RegisterCryptographicAlgorithm((EncryptionType)(-1), () => new NoopTransform());
            CryptoService.RegisterChecksumAlgorithm((ChecksumType)(-1), (signature, signatureData) => new NoopChecksum(signature, signatureData));

            this.SetHost();

            this.txtHost.TextChanged += this.Host_Changed;

            this.txtHost.Text = this.hostName;

            this.txtKey.TextChanged += this.Key_Changed;
        }

        public string Ticket
        {
            get => this.txtTicket.Text;
            set => this.txtTicket.Text = value;
        }

        public bool Persistent { get; set; } = true;

        private void Form1_Load(object sender, EventArgs e)
        {
            if (this.Persistent)
            {
                this.TryLoadPersistedSettings();
            }
            else if (!string.IsNullOrWhiteSpace(this.Ticket))
            {
                this.chkRemember.Checked = false;
                this.btnDecode_Click(sender, e);
            }

            if (this.IsHandleCreated)
            {
                this.Invoke((MethodInvoker)delegate ()
                {
                    this.TopMost = true;
                    this.TopMost = false;
                });
            }
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            this.cancellation.Cancel();
        }

        private void TryLoadPersistedSettings()
        {
            if (!Settings.Default.ShouldRemember)
            {
                this.chkRemember.Checked = false;

                return;
            }

            this.txtTicket.Text = Settings.Default.Ticket;
            this.txtKey.Text = Unprotect(Settings.Default.Secret);
            this.chkEncodedKey.Checked = Settings.Default.IsSecretEncoded;
            this.txtHost.Text = Settings.Default.Host;
            this.ddlKeyType.SelectedIndex = Settings.Default.SecretType;

            this.btnDecode_Click(this, EventArgs.Empty);
        }

        private void SetHost()
        {
            this.hostName = Environment.MachineName.ToLowerInvariant();
        }

        string hostName = "";

        private void Host_Changed(object sender, EventArgs e)
        {
            this.hostName = this.txtHost.Text;

            if (!string.IsNullOrWhiteSpace(this.hostName))
            {
                var hostLabel = this.hostName.Split('.').First();

                if (hostLabel.Length > 15)
                {
                    hostLabel = hostLabel.Substring(0, 15) + "...";
                }

                this.btnRequest.Text = string.Format(RequestTemplateText, hostLabel);
            }
            else
            {
                this.btnRequest.Text = string.Format(RequestTemplateText, "<host>");
            }
        }

        private void Key_Changed(object sender, EventArgs e)
        {
            this.MessageView.Reset();
        }

        private void btnDecode_Click(object sender, EventArgs e)
        {
            try
            {
                if (this.running)
                {
                    this.StopDecode();
                    return;
                }

                this.Decode();
            }
            catch (Exception ex)
            {
                this.ShowError(ex);
            }
        }

        private void Decode()
        {
            if (this.chkRemember.Checked)
            {
                this.TryPersistingValues();
            }
            else
            {
                this.ResetPersistedValues();
            }

            if (string.IsNullOrWhiteSpace(this.txtTicket.Text))
            {
                return;
            }

            this.Decode(this.txtTicket.Text);
        }

        private KeyTable CreateKeytab()
        {
            if (this.table != null)
            {
                return this.table;
            }

            if (string.Equals("Password", this.ddlKeyType.SelectedItem?.ToString(), StringComparison.OrdinalIgnoreCase))
            {
                var domain = Environment.GetEnvironmentVariable("USERDNSDOMAIN") ?? "";

                var host = this.txtHost.Text;

                var split = host.Split(new[] { '.' }, 2);

                if (split.Length == 2)
                {
                    host = split[0];
                    domain = split[1];
                }

                return this.EncodePassword(domain, host);
            }
            else
            {
                return this.EncodeKerberosKey();
            }
        }

        private KeyTable EncodeKerberosKey()
        {
            var bytes = Convert.FromBase64String(this.txtKey.Text);

            var keys = new List<KerberosKey>();

            foreach (EncryptionType etype in Enum.GetValues(typeof(EncryptionType)))
            {
                if (CryptoService.SupportsEType(etype, allowWeakCrypto: true) && etype != EncryptionType.NULL)
                {
                    var transformer = CryptoService.CreateTransform(etype);

                    keys.Add(new KerberosKey(key: bytes.Take(transformer.KeySize).ToArray(), etype: etype));
                }
            }

            return new KeyTable(keys.ToArray());
        }

        private KeyTable EncodePassword(string domain, string host)
        {
            if (string.IsNullOrWhiteSpace(this.txtKey.Text))
            {
                return null;
            }

            KeyTable key;

            if (this.chkEncodedKey.Checked)
            {
                var bytes = Convert.FromBase64String(this.txtKey.Text);

                key = new KeyTable(
                    new KerberosKey(
                        password: bytes,
                        principal: new PrincipalName(PrincipalNameType.NT_SRV_HST, domain, new[] { Environment.MachineName }),
                        host: host
                    )
                );
            }
            else
            {
                key = new KeyTable(
                    new KerberosKey(
                        this.txtKey.Text,
                        principalName: new PrincipalName(PrincipalNameType.NT_SRV_HST, domain, new[] { Environment.MachineName }),
                        host: string.IsNullOrWhiteSpace(host) ? null : host
                    )
                );
            }

            return key;
        }

        private void ResetPersistedValues()
        {
            try
            {
                Settings.Default.Reset();
                Settings.Default.Save();
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }
        }

        private void TryPersistingValues()
        {
            try
            {
                Settings.Default.ShouldRemember = true;

                Settings.Default.Ticket = this.txtTicket.Text;
                Settings.Default.Secret = Protect(this.txtKey.Text);
                Settings.Default.IsSecretEncoded = this.chkEncodedKey.Checked;
                Settings.Default.Host = this.txtHost.Text;
                Settings.Default.SecretType = this.ddlKeyType.SelectedIndex;

                Settings.Default.Save();
            }
            catch (Exception ex)
            {
                Debug.WriteLine(ex);
            }
        }

        private static string Protect(string text)
        {
            if (string.IsNullOrWhiteSpace(text))
            {
                return text;
            }

            var protectedSecret = ProtectedData.Protect(
                Encoding.Unicode.GetBytes(text),
                null,
                DataProtectionScope.CurrentUser
            );

            return Convert.ToBase64String(protectedSecret);
        }

        private static string Unprotect(string secret)
        {
            if (string.IsNullOrWhiteSpace(secret))
            {
                return secret;
            }

            var unprotected = ProtectedData.Unprotect(
                Convert.FromBase64String(secret),
                null,
                DataProtectionScope.CurrentUser
            );

            return Encoding.Unicode.GetString(unprotected);
        }

        private static string StripWhitespace(string ticket)
        {
            return ticket.Replace("\r", "").Replace("\n", "").Replace("\t", "").Replace(" ", "");
        }

        private static object GenerateFormattedKeyTable(KeyTable keytab)
        {
            if (keytab == null)
            {
                return null;
            }

            var keys = keytab.Entries.Select(k =>
            {
                var keyBytes = k.Key.GetKey(
                    CryptoService.CreateTransform(EncryptionType.NULL)
                );

                var key = new KerberosKey(
                    Encoding.Unicode.GetString(keyBytes.ToArray()),
                    k.Principal
                );

                return new
                {
                    k.EncryptionType,
                    k.Length,
                    k.Timestamp,
                    k.Version,
                    key.Host,
                    key.PasswordBytes,
                    KeyPrincipalName = key.PrincipalName,
                    key.Salt
                };
            });

            var table = new
            {
                keytab.FileVersion,
                keytab.KerberosVersion,
                Entries = keys.ToArray()
            };

            return table;
        }

        private void Decode(string ticket)
        {
            this.MessageView.Reset();

            _ = DecodeMessage(ticket);
        }

        private Task DecodeMessage(string ticket)
        {
            return Task.Run(() =>
            {
                try
                {
                    this.StartDecode();

                    DecodeInternal(ticket);
                }
                finally
                {
                    this.StopDecode();
                }
            });
        }

        private void StopDecode()
        {
            this.Invoke((MethodInvoker)delegate ()
            {
                this.lblDecode.Text = "";
                this.btnDecode.Text = "Decode";
                this.cancellation.Cancel();
                this.running = false;
            });
        }

        private void StartDecode()
        {
            this.Invoke((MethodInvoker)delegate ()
            {
                this.btnDecode.Text = "Abort";
                this.cancellation = new();
                this.running = true;
            });
        }

        private void DecodeInternal(string ticket)
        {
            if (!TryDecodeHex(ticket, out byte[] ticketBytes))
            {
                if (!TryDecodeBase64(ticket, out ticketBytes))
                {
                    throw new FormatException("Unknown Kerberos message format");
                }
            }

            bool handleCreated = this.IsHandleCreated;

            (object thing, string label) decoded = (null, null);

            Parallel.For(
                0,
                ticketBytes.Length,
                new ParallelOptions { CancellationToken = this.cancellation.Token, MaxDegreeOfParallelism = 1 },
                (i, state) =>
                {
                    var forwards = new ReadOnlyMemory<byte>(ticketBytes)[i..];

                    if (handleCreated)
                    {
                        this.Invoke((MethodInvoker)delegate ()
                        {
                            this.lblDecode.Text = $"Decoding 0x{i:x4}";
                        });
                    }

                    for (var j = forwards.Length; j > 0; j--)
                    {
                        if (state.IsStopped)
                        {
                            break;
                        }

                        var backwards = forwards[..j];

                        try
                        {
                            var processed = ProcessMessage(backwards, "Decoded");

                            if (processed.thing != null && !state.IsStopped)
                            {
                                state.Stop();

                                decoded = processed;
                            }
                        }
                        catch (Exception e) when (e is not InvalidOperationException)
                        {
                            continue;
                        }
                    }
                });

            if (decoded.thing != null)
            {
                this.Invoke((MethodInvoker)delegate ()
                {
                    this.MessageView.RenderObject(decoded.thing, decoded.label, this.CreateKeytab());
                });
            }
        }

        internal (object thing, string label) ProcessMessage(ReadOnlyMemory<byte> message, string source = null)
        {
            object parsedMessage = null;

            try
            {
                parsedMessage = MessageParser.Parse(message);
            }
            catch { }

            if (parsedMessage == null)
            {
                try
                {
                    var nego = NegotiationToken.Decode(message);

                    if (nego.ResponseToken != null)
                    {
                        parsedMessage = MessageParser.Parse(nego.ResponseToken.ResponseToken.Value);
                    }
                }
                catch { }
            }

            if (parsedMessage is NtlmContextToken ntlm)
            {
                return ProcessNtlm(ntlm, source);
            }
            else if (parsedMessage is NegotiateContextToken nego)
            {
                return ProcessNegotiate(nego.Token, source);
            }
            else if (parsedMessage is KerberosContextToken kerb)
            {
                return ProcessKerberos(kerb, source);
            }
            else if (parsedMessage is IAKerbContextToken iakerb)
            {
                return ProcessIAKerb(iakerb, source);
            }

            try
            {
                if (KdcProxyMessage.TryDecode(message, out KdcProxyMessage proxyMessage))
                {
                    return ProcessKdcProxy(proxyMessage, source);
                }
            }
            catch { }

            try
            {
                return ProcessUnknownMessage(message, "Unknown");
            }
            catch { }

            return (null, null);
        }

        private (object thing, string label) ProcessIAKerb(IAKerbContextToken iakerb, string source)
        {
            var (thing, label) = ProcessUnknownMessage(iakerb.Body, source);

            return ExplodeObject(
                new Dictionary<string, object>
                {
                    { "Wire", iakerb },
                    { label, thing }
                },
                $"IAKerb Message ({source})"
            );
        }

        private class PotentialKerberosMessages
        {
            public KrbAsReq AsReq { get; set; }
            public KrbAsRep AsRep { get; set; }

            public KrbTgsReq TgsReq { get; set; }
            public KrbTgsRep TgsRep { get; set; }

            public KrbError KrbError { get; set; }
        }

        private (object thing, string label) ProcessKdcProxy(KdcProxyMessage proxyMessage, string source)
        {
            var message = proxyMessage.UnwrapMessage();

            return ProcessUnknownMessage(message, source);
        }

        private (object thing, string label) ProcessUnknownMessage(ReadOnlyMemory<byte> message, string source)
        {
            var kdcBody = new PotentialKerberosMessages
            {
                AsReq = TryDecode(message, m => KrbAsReq.DecodeApplication(m)),
                AsRep = TryDecode(message, m => KrbAsRep.DecodeApplication(m)),
                TgsReq = TryDecode(message, m => KrbTgsReq.DecodeApplication(m)),
                TgsRep = TryDecode(message, m => KrbTgsRep.DecodeApplication(m)),
                KrbError = TryDecode(message, m => KrbError.DecodeApplication(m))
            };

            if (kdcBody.AsReq != null)
            {
                return ExplodeObject(kdcBody.AsReq, $"AS-REQ ({source})");
            }
            else if (kdcBody.AsRep != null)
            {
                return ExplodeObject(kdcBody.AsRep, $"AS-REP ({source})");
            }
            else if (kdcBody.TgsReq != null)
            {
                return ExplodeObject(kdcBody.TgsReq, $"TGS-REQ ({source})");
            }
            else if (kdcBody.TgsRep != null)
            {
                return ExplodeObject(kdcBody.TgsRep, $"TGS-REP ({source})");
            }
            else if (kdcBody.KrbError != null)
            {
                return ExplodeObject(kdcBody.KrbError, $"Krb-Error ({source})");
            }

            return (null, null);
        }

        private static T TryDecode<T>(ReadOnlyMemory<byte> kerbMessage, Func<ReadOnlyMemory<byte>, T> p)
        {
            try
            {
                return p(kerbMessage);
            }
            catch
            {
                return default;
            }
        }

        private (object thing, string label) ProcessKerberos(KerberosContextToken kerb, string source)
        {
            if (kerb.KrbApReq != null)
            {
                return ExplodeObject(kerb.KrbApReq, $"Kerberos AP-REQ ({source})");
            }
            else if (kerb.KrbApRep != null)
            {
                return ExplodeObject(kerb.KrbApRep, $"Kerberos AP-REP ({source})");
            }

            return (null, null);
        }

        private (object thing, string label) ProcessNegotiate(NegotiationToken token, string source)
        {
            var parsed = MessageParser.Parse(token.InitialToken.MechToken.Value);

            var (thing, label) = ProcessMessage(token.InitialToken.MechToken.Value, source);

            return ExplodeObject(
                new Dictionary<string, object>
                {
                    { "Wire", token },
                    { "Mech Token", parsed },
                    { label, thing }
                },
                $"Negotiate Message ({source})"
            );
        }

        private (object thing, string label) ProcessNtlm(NtlmContextToken ntlm, string source)
        {
            return ExplodeObject(ntlm.Token, $"NTLM Message ({source})");
        }

        private (object thing, string label) ExplodeObject(object thing, string baseNodeText)
        {
            return (thing, baseNodeText);
        }

        private static bool TryDecodeHex(string ticket, out byte[] ticketBytes)
        {
            ticketBytes = null;

            try
            {
                ticket = StripWhitespace(ticket);
                ticketBytes = StringToByteArray(ticket);
                return true;
            }
            catch
            {
                return false;
            }
        }

        private static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private static bool TryDecodeBase64(string ticket, out byte[] ticketBytes)
        {
            ticketBytes = null;

            try
            {
                ticket = StripWhitespace(ticket);

                ticketBytes = Convert.FromBase64String(ticket);

                return true;
            }
            catch
            {
                return false;
            }
        }

        private void btnDecodeLocal_Click(object sender, EventArgs e)
        {
            try
            {
                using (var secret = new LSASecret("$MACHINE.ACC"))
                {
                    secret.GetSecret(out byte[] bytes);

                    this.txtKey.Text = Convert.ToBase64String(bytes);
                }

                this.chkEncodedKey.Checked = true;

                this.btnDecode_Click(sender, e);
            }
            catch (Exception ex)
            {
                this.ShowError(ex);
            }
        }

        private void ShowError(Exception ex)
        {
            this.MessageView.Reset();

            var sb = new StringBuilder();

            sb.Append("Decoding Failed. \r\n\r\n");

            if (ex is AggregateException agg)
            {
                foreach (var aggEx in agg.InnerExceptions)
                {
                    sb.AppendFormat("{0}\r\n\r\n", aggEx.Message);
                }
            }
            else
            {
                sb.Append(ex.Message);
            }

            sb.AppendLine();
            sb.AppendLine();
            sb.Append(ex.StackTrace);

            MessageBox.Show(
                this,
                sb.ToString(),
                ex.Message,
                MessageBoxButtons.OK,
                MessageBoxIcon.Error
            );
        }

        private void RequestLocalTicket()
        {
            if (string.IsNullOrWhiteSpace(this.hostName))
            {
                this.SetHost();

                this.txtHost.Text = this.hostName;
            }

            var context = new SspiContext(spn: this.hostName);

            byte[] tokenBytes = context.RequestToken();

            this.txtTicket.Text = Convert.ToBase64String(tokenBytes);
        }

        private void btnLoadKeytab_Click(object sender, EventArgs e)
        {
            using (var dialog = new OpenFileDialog())
            {
                var result = dialog.ShowDialog(this);

                if (result == DialogResult.OK)
                {
                    this.LoadKeytab(dialog.FileName);
                }
            }
        }

        private void LoadKeytab(string fileName)
        {
            try
            {
                var keytab = new KeyTable(File.ReadAllBytes(fileName));

                if (keytab.Entries.Any())
                {
                    this.table = keytab;

                    this.lblKeytab.Text = fileName;

                    if (string.IsNullOrWhiteSpace(this.txtTicket.Text))
                    {
                        var formatted = GenerateFormattedKeyTable(this.table);

                        this.MessageView.RenderObject(new { KeyTable = formatted }, "Keytab", this.CreateKeytab());
                    }
                }
            }
            catch (Exception ex)
            {
                this.lblKeytab.Text = "";
                this.ShowError(ex);
            }
        }

        private void btnClear_Click(object sender, EventArgs e)
        {
            this.splitContainer1.SplitterDistance = this.splitter1Default;

            this.txtTicket.Text = "";
            this.txtHost.Text = "";
            this.txtKey.Text = "";
            this.chkEncodedKey.Checked = false;

            this.MessageView.Reset();
            this.table = null;
            this.lblKeytab.Text = "";
        }

        private void btnRequest_Click(object sender, EventArgs e)
        {
            try
            {
                this.RequestLocalTicket();
            }
            catch (Exception ex)
            {
                this.ShowError(ex);
            }
        }

        private void ExportWireshark(object sender, EventArgs e)
        {
            using (var dialog = new SaveFileDialog
            {
                Filter = "txt files (*.txt)|*.txt|All files (*.*)|*.*",
                FilterIndex = 2,
                RestoreDirectory = true
            })
            {
                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    using (var stream = dialog.OpenFile())
                    {
                        this.ExportWireSharkFile(stream);
                    }
                }
            }
        }

        private void ExportKeytab(object sender, EventArgs e)
        {
            using (var dialog = new SaveFileDialog
            {
                Filter = "keytab files (*.ketab)|*.keytab|All files (*.*)|*.*",
                FilterIndex = 2,
                RestoreDirectory = true
            })
            {
                if (dialog.ShowDialog() == DialogResult.OK)
                {
                    using (var stream = dialog.OpenFile())
                    {
                        this.ExportKeytabFile(stream);
                    }
                }
            }
        }

        private void ExportKeytabFile(Stream stream)
        {
            var keytab = this.CreateKeytab();

            using (var writer = new BinaryWriter(stream))
            {
                keytab.Write(writer);

                writer.Flush();
            }
        }

        private void ExportWireSharkFile(Stream stream)
        {
            var header = new StringBuilder();

            header.AppendLine("GET http://fakeserver/fakenegotiate HTTP/1.1");
            header.AppendLine("User-Agent: kerberos/net");
            header.AppendLine("Pragma: no-cache");
            header.AppendLine("Host: fakeserver");
            header.AppendFormat("WWW-Authenticate: Negotiate {0}\r\n", this.txtTicket.Text);
            header.AppendLine("Accept-Language: en-US");
            header.AppendLine("Accept-Encoding: gzip, deflate");
            header.AppendLine("Connection: close");
            header.AppendLine();

            using (var writer = new StreamWriter(stream))
            {
                writer.Write(Hex.DumpHex(Encoding.ASCII.GetBytes(header.ToString())));
                writer.Flush();
            }
        }

        private void ddlKeyType_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (ddlKeyType.SelectedIndex == 0) // password
            {
                this.chkEncodedKey.Visible = true;
                this.txtHost.Visible = true;
                this.label4.Visible = true;
            }
            else
            {
                this.chkEncodedKey.Visible = false;
                this.txtHost.Visible = false;
                this.label4.Visible = false;
            }
        }
    }
}
