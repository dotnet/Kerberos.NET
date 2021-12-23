namespace KerbDump
{
    partial class Form1
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.button1 = new System.Windows.Forms.Button();
            this.splitContainer1 = new System.Windows.Forms.SplitContainer();
            this.label2 = new System.Windows.Forms.Label();
            this.ddlKeyType = new System.Windows.Forms.ComboBox();
            this.chkRemember = new System.Windows.Forms.CheckBox();
            this.label4 = new System.Windows.Forms.Label();
            this.txtHost = new System.Windows.Forms.TextBox();
            this.chkEncodedKey = new System.Windows.Forms.CheckBox();
            this.txtKey = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.txtTicket = new System.Windows.Forms.TextBox();
            this.treeView1 = new System.Windows.Forms.TreeView();
            this.btnDecodeLocal = new System.Windows.Forms.Button();
            this.btnLoadKeytab = new System.Windows.Forms.Button();
            this.lblKeytab = new System.Windows.Forms.Label();
            this.btnClear = new System.Windows.Forms.Button();
            this.btnRequest = new System.Windows.Forms.Button();
            this.btnExport = new System.Windows.Forms.Button();
            this.lblDecode = new System.Windows.Forms.Label();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).BeginInit();
            this.splitContainer1.Panel1.SuspendLayout();
            this.splitContainer1.Panel2.SuspendLayout();
            this.splitContainer1.SuspendLayout();
            this.SuspendLayout();
            // 
            // button1
            // 
            this.button1.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.button1.Location = new System.Drawing.Point(1640, 773);
            this.button1.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(174, 36);
            this.button1.TabIndex = 1;
            this.button1.Text = "Decode";
            this.button1.UseVisualStyleBackColor = true;
            this.button1.Click += new System.EventHandler(this.button1_Click);
            // 
            // splitContainer1
            // 
            this.splitContainer1.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.splitContainer1.Location = new System.Drawing.Point(1, 19);
            this.splitContainer1.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.splitContainer1.Name = "splitContainer1";
            // 
            // splitContainer1.Panel1
            // 
            this.splitContainer1.Panel1.Controls.Add(this.label2);
            this.splitContainer1.Panel1.Controls.Add(this.ddlKeyType);
            this.splitContainer1.Panel1.Controls.Add(this.chkRemember);
            this.splitContainer1.Panel1.Controls.Add(this.label4);
            this.splitContainer1.Panel1.Controls.Add(this.txtHost);
            this.splitContainer1.Panel1.Controls.Add(this.chkEncodedKey);
            this.splitContainer1.Panel1.Controls.Add(this.txtKey);
            this.splitContainer1.Panel1.Controls.Add(this.label1);
            this.splitContainer1.Panel1.Controls.Add(this.txtTicket);
            // 
            // splitContainer1.Panel2
            // 
            this.splitContainer1.Panel2.Controls.Add(this.treeView1);
            this.splitContainer1.Size = new System.Drawing.Size(1829, 701);
            this.splitContainer1.SplitterDistance = 322;
            this.splitContainer1.SplitterWidth = 6;
            this.splitContainer1.TabIndex = 2;
            // 
            // label2
            // 
            this.label2.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(5, 423);
            this.label2.Margin = new System.Windows.Forms.Padding(5, 0, 5, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(68, 20);
            this.label2.TabIndex = 9;
            this.label2.Text = "Key Type";
            // 
            // ddlKeyType
            // 
            this.ddlKeyType.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.ddlKeyType.FormattingEnabled = true;
            this.ddlKeyType.Items.AddRange(new object[] {
            "Password",
            "Kerberos Key"});
            this.ddlKeyType.Location = new System.Drawing.Point(5, 451);
            this.ddlKeyType.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.ddlKeyType.Name = "ddlKeyType";
            this.ddlKeyType.Size = new System.Drawing.Size(314, 28);
            this.ddlKeyType.TabIndex = 8;
            this.ddlKeyType.SelectedIndexChanged += new System.EventHandler(this.ddlKeyType_SelectedIndexChanged);
            // 
            // chkRemember
            // 
            this.chkRemember.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.chkRemember.AutoSize = true;
            this.chkRemember.Checked = true;
            this.chkRemember.CheckState = System.Windows.Forms.CheckState.Checked;
            this.chkRemember.Location = new System.Drawing.Point(5, 667);
            this.chkRemember.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.chkRemember.Name = "chkRemember";
            this.chkRemember.Size = new System.Drawing.Size(104, 24);
            this.chkRemember.TabIndex = 7;
            this.chkRemember.Text = "Remember";
            this.chkRemember.UseVisualStyleBackColor = true;
            // 
            // label4
            // 
            this.label4.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(5, 595);
            this.label4.Margin = new System.Windows.Forms.Padding(5, 0, 5, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(40, 20);
            this.label4.TabIndex = 6;
            this.label4.Text = "Host";
            // 
            // txtHost
            // 
            this.txtHost.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtHost.Location = new System.Drawing.Point(5, 620);
            this.txtHost.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.txtHost.Name = "txtHost";
            this.txtHost.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtHost.Size = new System.Drawing.Size(313, 27);
            this.txtHost.TabIndex = 5;
            // 
            // chkEncodedKey
            // 
            this.chkEncodedKey.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.chkEncodedKey.AutoSize = true;
            this.chkEncodedKey.Location = new System.Drawing.Point(150, 667);
            this.chkEncodedKey.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.chkEncodedKey.Name = "chkEncodedKey";
            this.chkEncodedKey.Size = new System.Drawing.Size(168, 24);
            this.chkEncodedKey.TabIndex = 4;
            this.chkEncodedKey.Text = "Password is Encoded";
            this.chkEncodedKey.UseVisualStyleBackColor = true;
            // 
            // txtKey
            // 
            this.txtKey.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtKey.Location = new System.Drawing.Point(5, 491);
            this.txtKey.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.txtKey.Multiline = true;
            this.txtKey.Name = "txtKey";
            this.txtKey.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtKey.Size = new System.Drawing.Size(314, 91);
            this.txtKey.TabIndex = 2;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(5, 1);
            this.label1.Margin = new System.Windows.Forms.Padding(5, 0, 5, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(129, 20);
            this.label1.TabIndex = 1;
            this.label1.Text = "Encoded Message";
            // 
            // txtTicket
            // 
            this.txtTicket.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtTicket.Location = new System.Drawing.Point(5, 32);
            this.txtTicket.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.txtTicket.Multiline = true;
            this.txtTicket.Name = "txtTicket";
            this.txtTicket.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtTicket.Size = new System.Drawing.Size(313, 381);
            this.txtTicket.TabIndex = 0;
            // 
            // treeView1
            // 
            this.treeView1.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.treeView1.Location = new System.Drawing.Point(0, 0);
            this.treeView1.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.treeView1.Name = "treeView1";
            this.treeView1.Size = new System.Drawing.Size(1484, 696);
            this.treeView1.TabIndex = 3;
            // 
            // btnDecodeLocal
            // 
            this.btnDecodeLocal.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnDecodeLocal.Location = new System.Drawing.Point(1328, 773);
            this.btnDecodeLocal.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.btnDecodeLocal.Name = "btnDecodeLocal";
            this.btnDecodeLocal.Size = new System.Drawing.Size(304, 36);
            this.btnDecodeLocal.TabIndex = 3;
            this.btnDecodeLocal.Text = "Decode with LSA Secret";
            this.btnDecodeLocal.UseVisualStyleBackColor = true;
            this.btnDecodeLocal.Click += new System.EventHandler(this.btnDecodeLocal_Click);
            // 
            // btnLoadKeytab
            // 
            this.btnLoadKeytab.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnLoadKeytab.Location = new System.Drawing.Point(16, 773);
            this.btnLoadKeytab.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.btnLoadKeytab.Name = "btnLoadKeytab";
            this.btnLoadKeytab.Size = new System.Drawing.Size(142, 36);
            this.btnLoadKeytab.TabIndex = 4;
            this.btnLoadKeytab.Text = "Load Keytab";
            this.btnLoadKeytab.UseVisualStyleBackColor = true;
            this.btnLoadKeytab.Click += new System.EventHandler(this.btnLoadKeytab_Click);
            // 
            // lblKeytab
            // 
            this.lblKeytab.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.lblKeytab.AutoSize = true;
            this.lblKeytab.Location = new System.Drawing.Point(166, 781);
            this.lblKeytab.Margin = new System.Windows.Forms.Padding(5, 0, 5, 0);
            this.lblKeytab.Name = "lblKeytab";
            this.lblKeytab.Size = new System.Drawing.Size(64, 20);
            this.lblKeytab.TabIndex = 5;
            this.lblKeytab.Text = "Keytab...";
            // 
            // btnClear
            // 
            this.btnClear.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnClear.Location = new System.Drawing.Point(905, 773);
            this.btnClear.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.btnClear.Name = "btnClear";
            this.btnClear.Size = new System.Drawing.Size(137, 36);
            this.btnClear.TabIndex = 6;
            this.btnClear.Text = "Clear";
            this.btnClear.UseVisualStyleBackColor = true;
            this.btnClear.Click += new System.EventHandler(this.btnClear_Click);
            // 
            // btnRequest
            // 
            this.btnRequest.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnRequest.Location = new System.Drawing.Point(1050, 773);
            this.btnRequest.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.btnRequest.Name = "btnRequest";
            this.btnRequest.Size = new System.Drawing.Size(270, 36);
            this.btnRequest.TabIndex = 7;
            this.btnRequest.Text = "Request for";
            this.btnRequest.UseVisualStyleBackColor = true;
            this.btnRequest.Click += new System.EventHandler(this.btnRequest_Click);
            // 
            // btnExport
            // 
            this.btnExport.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnExport.Location = new System.Drawing.Point(1640, 729);
            this.btnExport.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.btnExport.Name = "btnExport";
            this.btnExport.Size = new System.Drawing.Size(174, 36);
            this.btnExport.TabIndex = 8;
            this.btnExport.Text = "Export";
            this.btnExport.UseVisualStyleBackColor = true;
            // 
            // lblDecode
            // 
            this.lblDecode.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.lblDecode.AutoSize = true;
            this.lblDecode.Location = new System.Drawing.Point(16, 737);
            this.lblDecode.Margin = new System.Windows.Forms.Padding(5, 0, 5, 0);
            this.lblDecode.Name = "lblDecode";
            this.lblDecode.Size = new System.Drawing.Size(83, 20);
            this.lblDecode.TabIndex = 10;
            this.lblDecode.Text = "Decoding...";
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 20F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1830, 828);
            this.Controls.Add(this.lblDecode);
            this.Controls.Add(this.btnExport);
            this.Controls.Add(this.btnRequest);
            this.Controls.Add(this.btnClear);
            this.Controls.Add(this.lblKeytab);
            this.Controls.Add(this.btnLoadKeytab);
            this.Controls.Add(this.btnDecodeLocal);
            this.Controls.Add(this.splitContainer1);
            this.Controls.Add(this.button1);
            this.Margin = new System.Windows.Forms.Padding(5, 4, 5, 4);
            this.Name = "Form1";
            this.Text = "Decode Kerberos Message";
            this.FormClosing += new System.Windows.Forms.FormClosingEventHandler(this.Form1_FormClosing);
            this.Load += new System.EventHandler(this.Form1_Load);
            this.splitContainer1.Panel1.ResumeLayout(false);
            this.splitContainer1.Panel1.PerformLayout();
            this.splitContainer1.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).EndInit();
            this.splitContainer1.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.SplitContainer splitContainer1;
        private System.Windows.Forms.TextBox txtTicket;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox txtKey;
        private System.Windows.Forms.CheckBox chkEncodedKey;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox txtHost;
        private System.Windows.Forms.Button btnDecodeLocal;
        private System.Windows.Forms.Button btnLoadKeytab;
        private System.Windows.Forms.Label lblKeytab;
        private System.Windows.Forms.Button btnClear;
        private System.Windows.Forms.Button btnRequest;
        private System.Windows.Forms.CheckBox chkRemember;
        private System.Windows.Forms.Button btnExport;
        private System.Windows.Forms.ComboBox ddlKeyType;
        private System.Windows.Forms.TreeView treeView1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label lblDecode;
    }
}

