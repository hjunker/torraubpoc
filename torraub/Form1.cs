using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Diagnostics;
using System.Net;
using System.Security;
using System.Threading;
using WmiLight;
using WmiLight.Wbem;
using System.Management;
using System.Management.Instrumentation;
using System.Runtime.InteropServices;
using System.IO;
using System.Windows.Controls;

namespace torraub
{
    public partial class Form1 : Form
    {
        static Thread testThread;
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);
        [DllImport("kernel32.dll")]
        static extern uint SuspendThread(IntPtr hThread);
        [DllImport("kernel32.dll")]
        static extern int ResumeThread(IntPtr hThread);
        [DllImport("kernel32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool CloseHandle(IntPtr handle);

        static Dictionary<String, ProcessInfo> ProcessList = new Dictionary<String, ProcessInfo>();
        static Dictionary<String, String> ignoredProcesses = new Dictionary<String, String>();
        static Dictionary<String, String> suspiciousProcesses = new Dictionary<String, String>();
        static DateTime lastcheck;
        static System.Windows.Forms.Timer myTimer = new System.Windows.Forms.Timer();

        public Form1()
        {
            InitializeComponent();
            button4.BackColor = Color.Red;
            button4.Text = "stopped (click to run)";
            String[] ignoredProcessesList = { "RuntimeBroker.exe", "svchost.exe", "chrome.exe", "devenv.exe", "SearchUI.exe", "SearchIndexer.exe", "explorer.exe", "MsMpEng.exe", "taskhostw.exe", "dllhost.exe", "MicrosoftEdge.exe", "ServiceHub.DataWarehouseHost.exe", "Registry", "OneApp.IGCC.WinService.exe", "msmdsrv.exe", "SearchApp.exe", "IGCCTray.exe", "OneDrive.exe" }; // "Dell.D3.WinSvc.exe"

            foreach (String tmp in ignoredProcessesList)
            {
                try
                {
                    ignoredProcesses.Add(tmp, tmp);
                }
                catch (Exception)
                { }
            }
        }

        private void button4_Click(object sender, EventArgs e)
        {
            if ((timer1 == null) || (timer1.Enabled == false))
            {
                timer1.Enabled = true;
                timer1.Start();
                button4.BackColor = Color.Green;
                button4.Text = "running (click to stop)";
            }
            else
            {
                timer1.Enabled = false;
                button4.BackColor = Color.Red;
                button4.Text = "stopped (click to run)";
            }
            /*
            if ((testThread == null) || (testThread.IsAlive == false))
            {
                testThread = new Thread(doChecks);
                testThread.Start();
                button4.BackColor = Color.Green;
            }
            else
            {
                testThread.Abort();
                button4.BackColor = Color.Red;
            }
            */
        }

        public void doChecks(Object myObject, EventArgs myEventArgs)
        {
            

            //Thread.Sleep(15 * 1000);
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            timer1.Stop();
            WmiConnection con = new WmiConnection();
            textBox1.Text += "running doChecks " + DateTime.Now + "\n";

            //Console.WriteLine("[LEARNING] currently ignoring the following processes (by name):");
            String ip = "";
            foreach (KeyValuePair<string, string> tmp in ignoredProcesses)
            {
                ip += "\"" + tmp.Key + "\", ";
            }
            ip = ip.Substring(0, ip.Length-2);
            textBox1.Text += "DEBUG: ignoredProcesses: " + ip + "\n";

            foreach (WmiObject process in con.CreateQuery("SELECT * FROM Win32_Process"))
            {
                /*
                foreach (String key in process.GetPropertyNames())
                {
                    Console.WriteLine(key + ": " + process.GetPropertyValue(key));
                }
                */

                ProcessInfo pi = new ProcessInfo();
                String p_ProcessId = "" + process["ProcessId"];
                String p_Name = "" + process["Name"];
                String p_Caption = "" + process["Caption"];
                String p_CommandLine = "" + process["CommandLine"];
                String p_ExecutablePath = "" + process["ExecutablePath"];
                String p_ParentProcessId = "" + process["ParentProcessId"];
                UInt64 p_WriteOperationCount = UInt64.Parse("" + process["WriteOperationCount"]);
                UInt64 p_WriteTransferCount = UInt64.Parse("" + process["WriteTransferCount"]) / 1000000;
                UInt64 p_ReadOperationCount = UInt64.Parse("" + process["ReadOperationCount"]);
                UInt64 p_ReadTransferCount = UInt64.Parse("" + process["ReadTransferCount"]) / 1000000;
                UInt64 p_OtherOperationCount = UInt64.Parse("" + process["OtherOperationCount"]);
                UInt64 p_OtherTransferCount = UInt64.Parse("" + process["OtherTransferCount"]) / 1000000;
                UInt64 p_KernelModeTime = UInt64.Parse("" + process["KernelModeTime"]);
                UInt64 p_UserModeTime = UInt64.Parse("" + process["UserModeTime"]);
                String p_CreationDate = "" + process["CreationDate"];
                p_CreationDate = p_CreationDate.Substring(0, 14);
                DateTime p_time = new DateTime(int.Parse(p_CreationDate.Substring(0, 4)), int.Parse(p_CreationDate.Substring(4, 2)), int.Parse(p_CreationDate.Substring(6, 2)), int.Parse(p_CreationDate.Substring(8, 2)), int.Parse(p_CreationDate.Substring(10, 2)), int.Parse(p_CreationDate.Substring(12, 2)));
                UInt64 avgwrites = 1000000 * 100 * p_WriteTransferCount / (p_KernelModeTime + p_UserModeTime + 1);

                pi.p_ProcessId = p_ProcessId;
                pi.p_Name = p_Name;
                pi.p_Caption = p_Caption;
                pi.p_CommandLine = p_CommandLine;
                pi.p_ExecutablePath = p_ExecutablePath;
                pi.p_ParentProcessId = p_ParentProcessId;
                pi.p_WriteOperationCount = p_WriteOperationCount;
                pi.p_WriteTransferCount = p_WriteTransferCount;
                pi.p_ReadOperationCount = p_ReadOperationCount;
                pi.p_ReadTransferCount = p_ReadTransferCount;
                pi.p_OtherOperationCount = p_OtherOperationCount;
                pi.p_OtherTransferCount = p_OtherTransferCount;
                pi.p_KernelModeTime = p_KernelModeTime;
                pi.p_UserModeTime = p_UserModeTime;
                pi.p_CreationDate = p_CreationDate;
                pi.p_time = p_time;
                pi.avgwrites = avgwrites;

                try
                {
                    ProcessList.Add(pi.p_ProcessId, pi);
                }
                catch (Exception ex)
                { }

                bool suspicious = false;

                // perform checks
                /*
                 * TODO: suspicious if
                 * - process not whitelisted
                 * - who is the parent? is it whitelisted?
                 * - WriteTransferCount / time > x?! --> avgwrites
                 * - ratio WriteOperationCount / ReadOperationCount / OtherOperationCount
                 * - ratio WriteTransferCount / ReadTransferCount / OtherTransferCount
                 * ...but not if application has been living for a long time (e.g. Microsoft.Photos.exe)
                 * */

                if ((p_WriteTransferCount > 10) & (avgwrites > 10)) suspicious = true;

                if (ignoredProcesses.ContainsKey(p_Name)) suspicious = false;
                if (ignoredProcesses.ContainsKey(p_Caption)) suspicious = false;
                //if (ignoredProcessesList.Any(p_Caption.Contains)) suspicious = false;

                if (suspicious & (!suspiciousProcesses.ContainsKey(p_ProcessId)))
                {
                    try
                    {
                        suspiciousProcesses.Add(p_ProcessId, p_Name);
                        Process processobj = Process.GetProcessById(int.Parse(p_ProcessId)); // throws exception if process does not exist
                                                                                             //OpenThread(ThreadAccess.SUSPEND_RESUME, false, uint.Parse(p_ProcessId));
                        /*
                        foreach (ProcessThread pT in processobj.Threads)
                        {
                            IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

                            if (pOpenThread == IntPtr.Zero)
                            {
                                continue;
                            }

                            SuspendThread(pOpenThread);

                            CloseHandle(pOpenThread);
                        }
                        */
                        //ListBoxItem item = new ListBoxItem();
                        //item.ToolTip = "suspended process " + pi.p_ProcessId + " / " + pi.p_Name;
                        //item.Name = (String)pi.p_ProcessId;
                        listBox1.Items.Add(pi.p_ProcessId);
                        textBox1.Text += "\nsuspended process " + pi.p_ProcessId + " / " + pi.p_Name;

                        /*
                        Console.WriteLine(p_ProcessId + "," + p_ParentProcessId + "," + p_time.ToString() + "," + p_CreationDate + "," + p_Caption + "," + p_Name + "," + p_ExecutablePath + "," + p_CommandLine + "," + avgwrites + "," + p_ReadTransferCount + "," + p_WriteTransferCount + "," + p_OtherTransferCount + "," + p_ReadOperationCount + "," + p_WriteOperationCount + "," + p_OtherOperationCount);
                        Console.WriteLine("suspend / kill / ignore / omit (once) this process (s/k/i/o)? ");
                        ConsoleKeyInfo resp = Console.ReadKey();
                        Console.WriteLine("");

                        if (resp.KeyChar == 'i')
                        {
                            try
                            {
                                ignoredProcesses.Add(p_Name, p_Name);
                            }
                            catch (Exception e)
                            { }
                        }

                        if (resp.KeyChar == 'k')
                        {
                            Process processobj = Process.GetProcessById(int.Parse(p_ProcessId));
                            processobj.Kill();
                        }

                        if (resp.KeyChar == 's')
                        {
                            Process processobj = Process.GetProcessById(int.Parse(p_ProcessId)); // throws exception if process does not exist
                            //OpenThread(ThreadAccess.SUSPEND_RESUME, false, uint.Parse(p_ProcessId));

                            foreach (ProcessThread pT in processobj.Threads)
                            {
                                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

                                if (pOpenThread == IntPtr.Zero)
                                {
                                    continue;
                                }

                                SuspendThread(pOpenThread);

                                CloseHandle(pOpenThread);
                            }

                        }
                        */
                    }
                    catch (Exception ex)
                    { }
                }

            }
            timer1.Start();
        }

        // KILL PROCESS
        private void button2_Click(object sender, EventArgs e)
        {
            // kill process with id selected in listBox1
            String pid = (String)listBox1.SelectedItem;
            Process processobj = Process.GetProcessById(int.Parse(pid));
            processobj.Kill();
            textBox3.Text = "";
            listBox1.Items.RemoveAt(listBox1.SelectedIndex);
            suspiciousProcesses.Remove(pid);
        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            textBox2.Text = (String)listBox1.SelectedItem;
            String tmp = "";
            suspiciousProcesses.TryGetValue(textBox2.Text, out tmp);
            textBox3.Text = tmp;
        }

        // IGNORE PROCESS PERMANENTLY (currently not persistent)
        private void button3_Click(object sender, EventArgs e)
        {
            Debug.WriteLine("AM I ALIVE?!?!?!");
            String pid = (String)listBox1.SelectedItem; 
            ignoredProcesses.Add(textBox3.Text, textBox3.Text);
            textBox3.Text = "";
            suspiciousProcesses.Remove(pid);
            listBox1.Items.RemoveAt(listBox1.SelectedIndex);

            /*
            Process processobj = Process.GetProcessById(int.Parse(pid)); // throws exception if process does not exist
            //IntPtr pOpenThread1 = OpenThread(ThreadAccess.SUSPEND_RESUME, false, uint.Parse(pid));
            //ResumeThread(pOpenThread1);
            //CloseHandle(pOpenThread1);

            foreach (ProcessThread pT in processobj.Threads)
            {
                Debug.WriteLine("TRYING TO RESUME A THREAD");
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    Debug.WriteLine("RESUME FAILED!!!"); 
                    continue;
                }

                ResumeThread(pOpenThread);
                Debug.WriteLine("THREAD SHOULD BE RESUMED.");

                CloseHandle(pOpenThread);
            }
            */
        }

        // TODO: SUSPEND CURRENTLY NOT WORKING!!!
        // SUSPEND PROCESS
        private void button1_Click(object sender, EventArgs e)
        {
            String pid = (String)listBox1.SelectedItem;
            Process processobj = Process.GetProcessById(int.Parse(pid)); // throws exception if process does not exist
                                                                                 //OpenThread(ThreadAccess.SUSPEND_RESUME, false, uint.Parse(p_ProcessId));
            
            foreach (ProcessThread pT in processobj.Threads)
            {
                IntPtr pOpenThread = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)pT.Id);

                if (pOpenThread == IntPtr.Zero)
                {
                    continue;
                }

                SuspendThread(pOpenThread);

                CloseHandle(pOpenThread);
            }

            textBox3.Text = "";
            suspiciousProcesses.Remove(pid);
            listBox1.Items.RemoveAt(listBox1.SelectedIndex);

        }
    }
}
