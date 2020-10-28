using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace torraub
{
    class ProcessInfo
    {
        public String p_ProcessId;
        public String p_Name;
        public String p_Caption;
        public String p_CommandLine;
        public String p_ExecutablePath;
        public String p_ParentProcessId;
        public UInt64 p_WriteOperationCount;
        public UInt64 p_WriteTransferCount;
        public UInt64 p_ReadOperationCount;
        public UInt64 p_ReadTransferCount;
        public UInt64 p_OtherOperationCount;
        public UInt64 p_OtherTransferCount;
        public UInt64 p_KernelModeTime;
        public UInt64 p_UserModeTime;
        public String p_CreationDate;
        public DateTime p_time;
        public UInt64 avgwrites;
    }
}
