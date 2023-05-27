using KerbDump.Properties;
using Kerberos.NET;
using Kerberos.NET.Crypto;
using Kerberos.NET.Entities;
using Kerberos.NET.Win32;
using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

#pragma warning disable IDE1006 // Naming Styles

namespace KerbDump
{
    public partial class DecoderForm : Form
    {
        private const string RequestTemplateText = "Request for {0}";

        private readonly ContextMenuStrip exportMenu = new();
        private readonly CancellationTokenSource cancellation = new();

        private readonly int splitter1Default;

        private KeyTable table;

        private bool decryptDecoded = false;
        private byte[] ticketBytes = null;

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

            this.SetHost();

            this.txtHost.TextChanged += this.Host_Changed;

            this.txtHost.Text = this.hostName;
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

        private void btnDecode_Click(object sender, EventArgs e)
        {
            try
            {
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

            if (!string.IsNullOrWhiteSpace(this.txtKey.Text) || this.table != null)
            {
                this.decryptDecoded = true;
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

        private async Task<object> DecryptMessage(KeyTable key)
        {
            var validator = new KerberosValidator(key) { ValidateAfterDecrypt = ValidationActions.Pac };

            var decrypted = await validator.Validate(ticketBytes);

            var request = MessageParser.Parse(ticketBytes);

            var authenticated = await new KerberosAuthenticator(validator).Authenticate(ticketBytes) as KerberosIdentity;

            return new
            {
                Request = request,
                Decrypted = decrypted,
                Computed = new
                {
                    authenticated.Name,
                    authenticated.Restrictions,
                    authenticated.ValidationMode,
                    Claims = authenticated.Claims.Select(c => new { c.Type, c.Value })
                },
                KeyTable = GenerateFormattedKeyTable(key)
            };
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

            DecodeMessage(ticket).ContinueWith(async t =>
            {
                try
                {
                    object ticket;

                    if (decryptDecoded)
                    {
                        ticket = await DecryptMessage(this.CreateKeytab());
                    }
                    else
                    {
                        ticket = FormatTicket();
                    }

                    this.Invoke((MethodInvoker)delegate ()
                    {
                        this.MessageView.RenderObject(ticket, "Decoded Message");
                    });
                }
                catch (Exception ex)
                {
                    this.ShowError(ex);
                }
            });
        }

        private object FormatTicket()
        {
            if (this.ticketBytes == null)
            {
                return null;
            }

            var request = MessageParser.Parse(this.ticketBytes);

            var obj = new Dictionary<string, object>()
            {
                { $"Request (Length = {this.ticketBytes.Length})", request }
            };

            var nego = request as NegotiateContextToken;

            if (nego?.Token.InitialToken.MechToken != null)
            {
                obj["Negotiate"] = MessageParser.Parse(nego.Token.InitialToken.MechToken.Value);
            }

            obj["Keytab"] = GenerateFormattedKeyTable(this.table);

            return obj;
        }

        private Task DecodeMessage(string ticket)
        {
            return Task.Run(() => this.ticketBytes = DecodeInternal(ticket));
        }

        private byte[] DecodeInternal(string ticket)
        {
            if (!TryDecodeHex(ticket, out byte[] ticketBytes))
            {
                if (!TryDecodeBase64(ticket, out ticketBytes))
                {
                    throw new FormatException("Unknown Kerberos message format");
                }
            }

            bool handleCreated = this.IsHandleCreated;

            byte[] result = null;

            Parallel.For(
                0,
                ticketBytes.Length,
                new ParallelOptions { CancellationToken = this.cancellation.Token },
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
                        var decoded = MessageParser.Parse(backwards);

                        if (decoded != null && !state.IsStopped)
                        {
                            result = backwards.ToArray();
                            state.Stop();
                        }
                    }
                    catch (Exception e) when (e is not InvalidOperationException)
                    {
                        continue;
                    }
                }
            });

            return result;
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

                        this.MessageView.RenderObject(new { KeyTable = formatted }, "Keytab");
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
