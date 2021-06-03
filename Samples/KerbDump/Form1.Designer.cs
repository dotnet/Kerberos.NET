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
            this.ddlKeyType = new System.Windows.Forms.ComboBox();
            this.chkRemember = new System.Windows.Forms.CheckBox();
            this.label4 = new System.Windows.Forms.Label();
            this.txtHost = new System.Windows.Forms.TextBox();
            this.chkEncodedKey = new System.Windows.Forms.CheckBox();
            this.txtKey = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.txtTicket = new System.Windows.Forms.TextBox();
            this.splitContainer2 = new System.Windows.Forms.SplitContainer();
            this.txtDump = new System.Windows.Forms.TextBox();
            this.treeView1 = new System.Windows.Forms.TreeView();
            this.label2 = new System.Windows.Forms.Label();
            this.btnDecodeLocal = new System.Windows.Forms.Button();
            this.btnLoadKeytab = new System.Windows.Forms.Button();
            this.lblKeytab = new System.Windows.Forms.Label();
            this.btnClear = new System.Windows.Forms.Button();
            this.btnRequest = new System.Windows.Forms.Button();
            this.btnExport = new System.Windows.Forms.Button();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).BeginInit();
            this.splitContainer1.Panel1.SuspendLayout();
            this.splitContainer1.Panel2.SuspendLayout();
            this.splitContainer1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer2)).BeginInit();
            this.splitContainer2.Panel1.SuspendLayout();
            this.splitContainer2.Panel2.SuspendLayout();
            this.splitContainer2.SuspendLayout();
            this.SuspendLayout();
            // 
            // button1
            // 
            this.button1.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.button1.Location = new System.Drawing.Point(1435, 580);
            this.button1.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(152, 27);
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
            this.splitContainer1.Location = new System.Drawing.Point(14, 14);
            this.splitContainer1.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.splitContainer1.Name = "splitContainer1";
            // 
            // splitContainer1.Panel1
            // 
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
            this.splitContainer1.Panel2.Controls.Add(this.splitContainer2);
            this.splitContainer1.Panel2.Controls.Add(this.label2);
            this.splitContainer1.Size = new System.Drawing.Size(1573, 526);
            this.splitContainer1.SplitterDistance = 278;
            this.splitContainer1.SplitterWidth = 5;
            this.splitContainer1.TabIndex = 2;
            // 
            // ddlKeyType
            // 
            this.ddlKeyType.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.ddlKeyType.FormattingEnabled = true;
            this.ddlKeyType.Items.AddRange(new object[] {
            "Password",
            "Kerberos Key"});
            this.ddlKeyType.Location = new System.Drawing.Point(4, 342);
            this.ddlKeyType.Name = "ddlKeyType";
            this.ddlKeyType.Size = new System.Drawing.Size(271, 23);
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
            this.chkRemember.Location = new System.Drawing.Point(4, 496);
            this.chkRemember.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.chkRemember.Name = "chkRemember";
            this.chkRemember.Size = new System.Drawing.Size(84, 19);
            this.chkRemember.TabIndex = 7;
            this.chkRemember.Text = "Remember";
            this.chkRemember.UseVisualStyleBackColor = true;
            // 
            // label4
            // 
            this.label4.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.label4.AutoSize = true;
            this.label4.Location = new System.Drawing.Point(4, 443);
            this.label4.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(32, 15);
            this.label4.TabIndex = 6;
            this.label4.Text = "Host";
            // 
            // txtHost
            // 
            this.txtHost.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtHost.Location = new System.Drawing.Point(4, 462);
            this.txtHost.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.txtHost.Name = "txtHost";
            this.txtHost.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtHost.Size = new System.Drawing.Size(270, 23);
            this.txtHost.TabIndex = 5;
            // 
            // chkEncodedKey
            // 
            this.chkEncodedKey.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.chkEncodedKey.AutoSize = true;
            this.chkEncodedKey.Location = new System.Drawing.Point(169, 496);
            this.chkEncodedKey.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.chkEncodedKey.Name = "chkEncodedKey";
            this.chkEncodedKey.Size = new System.Drawing.Size(105, 19);
            this.chkEncodedKey.TabIndex = 4;
            this.chkEncodedKey.Text = "Key is Encoded";
            this.chkEncodedKey.UseVisualStyleBackColor = true;
            // 
            // txtKey
            // 
            this.txtKey.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtKey.Location = new System.Drawing.Point(4, 371);
            this.txtKey.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.txtKey.Multiline = true;
            this.txtKey.Name = "txtKey";
            this.txtKey.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtKey.Size = new System.Drawing.Size(271, 69);
            this.txtKey.TabIndex = 2;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(4, 14);
            this.label1.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(87, 15);
            this.label1.TabIndex = 1;
            this.label1.Text = "Encoded Ticket";
            // 
            // txtTicket
            // 
            this.txtTicket.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtTicket.Location = new System.Drawing.Point(4, 32);
            this.txtTicket.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.txtTicket.Multiline = true;
            this.txtTicket.Name = "txtTicket";
            this.txtTicket.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtTicket.Size = new System.Drawing.Size(270, 287);
            this.txtTicket.TabIndex = 0;
            // 
            // splitContainer2
            // 
            this.splitContainer2.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.splitContainer2.Location = new System.Drawing.Point(7, 32);
            this.splitContainer2.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.splitContainer2.Name = "splitContainer2";
            // 
            // splitContainer2.Panel1
            // 
            this.splitContainer2.Panel1.Controls.Add(this.txtDump);
            // 
            // splitContainer2.Panel2
            // 
            this.splitContainer2.Panel2.Controls.Add(this.treeView1);
            this.splitContainer2.Size = new System.Drawing.Size(1271, 472);
            this.splitContainer2.SplitterDistance = 418;
            this.splitContainer2.SplitterWidth = 5;
            this.splitContainer2.TabIndex = 4;
            // 
            // txtDump
            // 
            this.txtDump.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtDump.Location = new System.Drawing.Point(0, 3);
            this.txtDump.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.txtDump.Multiline = true;
            this.txtDump.Name = "txtDump";
            this.txtDump.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.txtDump.Size = new System.Drawing.Size(413, 464);
            this.txtDump.TabIndex = 1;
            // 
            // treeView1
            // 
            this.treeView1.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.treeView1.Location = new System.Drawing.Point(4, 3);
            this.treeView1.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.treeView1.Name = "treeView1";
            this.treeView1.Size = new System.Drawing.Size(832, 464);
            this.treeView1.TabIndex = 3;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(4, 14);
            this.label2.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(88, 15);
            this.label2.TabIndex = 2;
            this.label2.Text = "Decoded Ticket";
            // 
            // btnDecodeLocal
            // 
            this.btnDecodeLocal.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnDecodeLocal.Location = new System.Drawing.Point(1162, 580);
            this.btnDecodeLocal.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.btnDecodeLocal.Name = "btnDecodeLocal";
            this.btnDecodeLocal.Size = new System.Drawing.Size(266, 27);
            this.btnDecodeLocal.TabIndex = 3;
            this.btnDecodeLocal.Text = "Decode with LSA Secret";
            this.btnDecodeLocal.UseVisualStyleBackColor = true;
            this.btnDecodeLocal.Click += new System.EventHandler(this.btnDecodeLocal_Click);
            // 
            // btnLoadKeytab
            // 
            this.btnLoadKeytab.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnLoadKeytab.Location = new System.Drawing.Point(14, 580);
            this.btnLoadKeytab.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.btnLoadKeytab.Name = "btnLoadKeytab";
            this.btnLoadKeytab.Size = new System.Drawing.Size(124, 27);
            this.btnLoadKeytab.TabIndex = 4;
            this.btnLoadKeytab.Text = "Load Keytab";
            this.btnLoadKeytab.UseVisualStyleBackColor = true;
            this.btnLoadKeytab.Click += new System.EventHandler(this.btnLoadKeytab_Click);
            // 
            // lblKeytab
            // 
            this.lblKeytab.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.lblKeytab.AutoSize = true;
            this.lblKeytab.Location = new System.Drawing.Point(145, 586);
            this.lblKeytab.Margin = new System.Windows.Forms.Padding(4, 0, 4, 0);
            this.lblKeytab.Name = "lblKeytab";
            this.lblKeytab.Size = new System.Drawing.Size(0, 15);
            this.lblKeytab.TabIndex = 5;
            // 
            // btnClear
            // 
            this.btnClear.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnClear.Location = new System.Drawing.Point(792, 580);
            this.btnClear.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.btnClear.Name = "btnClear";
            this.btnClear.Size = new System.Drawing.Size(120, 27);
            this.btnClear.TabIndex = 6;
            this.btnClear.Text = "Clear";
            this.btnClear.UseVisualStyleBackColor = true;
            this.btnClear.Click += new System.EventHandler(this.btnClear_Click);
            // 
            // btnRequest
            // 
            this.btnRequest.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnRequest.Location = new System.Drawing.Point(919, 580);
            this.btnRequest.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.btnRequest.Name = "btnRequest";
            this.btnRequest.Size = new System.Drawing.Size(236, 27);
            this.btnRequest.TabIndex = 7;
            this.btnRequest.Text = "Request for";
            this.btnRequest.UseVisualStyleBackColor = true;
            this.btnRequest.Click += new System.EventHandler(this.btnRequest_Click);
            // 
            // btnExport
            // 
            this.btnExport.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnExport.Location = new System.Drawing.Point(1435, 547);
            this.btnExport.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.btnExport.Name = "btnExport";
            this.btnExport.Size = new System.Drawing.Size(152, 27);
            this.btnExport.TabIndex = 8;
            this.btnExport.Text = "Export";
            this.btnExport.UseVisualStyleBackColor = true;
            // 
            // Form1
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 15F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1601, 621);
            this.Controls.Add(this.btnExport);
            this.Controls.Add(this.btnRequest);
            this.Controls.Add(this.btnClear);
            this.Controls.Add(this.lblKeytab);
            this.Controls.Add(this.btnLoadKeytab);
            this.Controls.Add(this.btnDecodeLocal);
            this.Controls.Add(this.splitContainer1);
            this.Controls.Add(this.button1);
            this.Margin = new System.Windows.Forms.Padding(4, 3, 4, 3);
            this.Name = "Form1";
            this.Text = "Decode Kerberos Ticket";
            this.splitContainer1.Panel1.ResumeLayout(false);
            this.splitContainer1.Panel1.PerformLayout();
            this.splitContainer1.Panel2.ResumeLayout(false);
            this.splitContainer1.Panel2.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer1)).EndInit();
            this.splitContainer1.ResumeLayout(false);
            this.splitContainer2.Panel1.ResumeLayout(false);
            this.splitContainer2.Panel1.PerformLayout();
            this.splitContainer2.Panel2.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer2)).EndInit();
            this.splitContainer2.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.SplitContainer splitContainer1;
        private System.Windows.Forms.TextBox txtTicket;
        private System.Windows.Forms.TextBox txtDump;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox txtKey;
        private System.Windows.Forms.CheckBox chkEncodedKey;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox txtHost;
        private System.Windows.Forms.Button btnDecodeLocal;
        private System.Windows.Forms.TreeView treeView1;
        private System.Windows.Forms.SplitContainer splitContainer2;
        private System.Windows.Forms.Button btnLoadKeytab;
        private System.Windows.Forms.Label lblKeytab;
        private System.Windows.Forms.Button btnClear;
        private System.Windows.Forms.Button btnRequest;
        private System.Windows.Forms.CheckBox chkRemember;
        private System.Windows.Forms.Button btnExport;
        private System.Windows.Forms.ComboBox ddlKeyType;
    }
}

