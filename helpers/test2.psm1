Function UdpTest {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateSet("TCP", "UDP")]
        [string] $Protocol = "UDP",

        [Parameter(Mandatory = $true)]
        [string] $Source,

        [Parameter(Mandatory = $true)]
        [string] $Destination,

        [Parameter(Mandatory = $false)]
        [string] $TestName,

        [Parameter(Mandatory = $false)]
        [int] $BufferLength = 65536,

        [Parameter(Mandatory = $false)]
        [int] $Duration = 90,

        [Parameter(Mandatory = $false)]
        [int] $PacketCount = 10000,

        [Parameter(Mandatory = $false)]
        [int] $Iterations = 1000
    )

    $id = get-random
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        using System.Text;
        using System.Net;

        public static class Program
        {
            public static string UdpSender(IPAddress source, IPAddress destination, uint bufLength, int packetCount, int iterations)
            {
                int retVal = 0;
                Console.WriteLine("Allocate Buffers");
                var dataArray = new WSABUF[packetCount];
                for (int index = 0; index < packetCount; index++)
                {
                    var DataBuf = new WSABUF();
                    DataBuf.length = bufLength;
                    DataBuf.buf = Marshal.AllocHGlobal(new IntPtr(bufLength));


                    dataArray[index] = DataBuf;
                }

                Console.WriteLine("WSAStartup");
                var wsaData = new WSAData();
                int retVal2 = WSAStartup(MakeWord(2, 2), out wsaData);
                if (retVal2 != 0)
                {
                    Console.WriteLine("Error {0} calling WSAStartup", WSAGetLastError());
                }
                Console.WriteLine("WSASocket");
                IntPtr socket = WSASocket(ADDRESS_FAMILIES.AF_INET, SOCKET_TYPE.SOCK_DGRAM, PROTOCOL.IPPROTO_UDP, IntPtr.Zero, 0, 0);
                if (socket.ToInt64() == -1)
                {
                    Console.WriteLine("Error {0} calling WSASocket", WSAGetLastError());
                }

                Console.WriteLine("setsockopt");
                uint sendBufferSize = 1472;
                retVal = setsockopt(socket, SocketOptionLevel.Udp, SocketOptionName.UDP_SEND_MSG_SIZE, ref sendBufferSize, Marshal.SizeOf(sendBufferSize));
                if (retVal != 0)
                {
                    Console.WriteLine("Error {0} calling setsockopt", WSAGetLastError());
                }

                Console.WriteLine("bind {0}:{1}", source, 8888);
                var bindAddress = ConvertFromIpAddress(source, 8888);
                retVal = bind(socket, ref bindAddress, Marshal.SizeOf(bindAddress));
                if (retVal != 0)
                {
                    Console.WriteLine("Error {0} calling bind", WSAGetLastError());
                }
                
                Console.WriteLine("Send {0}", bindAddress);
                var sendAddress = ConvertFromIpAddress(destination, 8888);
                for (int looper = 0; looper < iterations; looper++)
                {

                    UInt32 bytesSent;
                    retVal = WSASendTo(socket, dataArray, Convert.ToUInt32(packetCount), out bytesSent, 0, ref sendAddress, Marshal.SizeOf(sendAddress), IntPtr.Zero, IntPtr.Zero);
                }

                Console.WriteLine(retVal);

                Console.WriteLine("closesocket");
                retVal = closesocket(socket);
                if (retVal != 0)
                {
                    Console.WriteLine("Error {0} calling closesocket" , WSAGetLastError());
                }

                retVal = WSACleanup();
                if (retVal != 0)
                {
                    Console.WriteLine("Error calling WSACleanup");
                }

                for (int index = 0; index < packetCount; index++)
                {
                    Marshal.FreeHGlobal(dataArray[index].buf);
                }
                return "done";
            }

            public static string TcpSender(IPAddress source, IPAddress destination, uint bufLength, int packetCount, int iterations)
            {
                int retVal = 0;
                Console.WriteLine("Allocate Buffers");
                var dataArray = new WSABUF[packetCount];
                for (int index = 0; index < packetCount; index++)
                {
                    var DataBuf = new WSABUF();
                    DataBuf.length = bufLength;
                    DataBuf.buf = Marshal.AllocHGlobal(new IntPtr(bufLength));


                    dataArray[index] = DataBuf;
                }

                Console.WriteLine("WSAStartup");
                var wsaData = new WSAData();
                int retVal2 = WSAStartup(MakeWord(2, 2), out wsaData);
                if (retVal2 != 0)
                {
                    Console.WriteLine("Error {0} calling WSAStartup", WSAGetLastError());
                }
                Console.WriteLine("WSASocket");
                IntPtr socket = WSASocket(ADDRESS_FAMILIES.AF_INET, SOCKET_TYPE.SOCK_STREAM, PROTOCOL.IPPROTO_TCP, IntPtr.Zero, 0, 0);
                if (socket.ToInt64() == -1)
                {
                    Console.WriteLine("Error {0} calling WSASocket", WSAGetLastError());
                }

                Console.WriteLine("setsockopt");
                uint sendBufferSize = 1472;
                retVal = setsockopt(socket, SocketOptionLevel.Tcp, SocketOptionName.UDP_SEND_MSG_SIZE, ref sendBufferSize, Marshal.SizeOf(sendBufferSize));
                if (retVal != 0)
                {
                    Console.WriteLine("Error {0} calling setsockopt", WSAGetLastError());
                }

                Console.WriteLine("Connect {0}:{1}", source, 8888);
                var bindAddress = ConvertFromIpAddress(destination, 8888);
                retVal = connect(socket, ref bindAddress, Marshal.SizeOf(bindAddress));
                if (retVal != 0)
                {
                    Console.WriteLine("Error {0} calling bind", WSAGetLastError());
                }
                
                Console.WriteLine("Send {0}", bindAddress);
                var sendAddress = ConvertFromIpAddress(destination, 8888);
                for (int looper = 0; looper < iterations; looper++)
                {

                    UInt32 bytesSent;
                    retVal = WSASend(socket, dataArray, Convert.ToUInt32(packetCount), out bytesSent, 0, IntPtr.Zero, IntPtr.Zero);
                }

                if (retVal != 0)
                {
                    Console.WriteLine("Error {0} calling WSASendTo" , WSAGetLastError());
                }


                Console.WriteLine("closesocket");
                retVal = closesocket(socket);
                if (retVal != 0)
                {
                    Console.WriteLine("Error {0} calling closesocket" , WSAGetLastError());
                }

                retVal = WSACleanup();
                if (retVal != 0)
                {
                    Console.WriteLine("Error calling WSACleanup");
                }

                for (int index = 0; index < packetCount; index++)
                {
                    Marshal.FreeHGlobal(dataArray[index].buf);
                }
                return "done";
            }

            internal static UInt16 MakeWord(byte low, byte high)
            {
                return Convert.ToUInt16(((uint)high << 8) | low);
            }

            internal static in_addr ConvertFromIpAddress(IPAddress address)
            {
                var inAddr = new in_addr();
                inet_pton(ADDRESS_FAMILIES.AF_INET, address.ToString(), ref inAddr);
                /*
                var addressBytes = address.GetAddressBytes();
                inAddr.s_b1 = addressBytes[0];
                inAddr.s_b2 = addressBytes[1];
                inAddr.s_b3 = addressBytes[2];
                inAddr.s_b4 = addressBytes[3];
                */
                return inAddr;
            }
            internal static sockaddr_in ConvertFromIpAddress(IPAddress address, ushort port)
            {
                var sockaddr = new sockaddr_in();
                sockaddr.sin_family = ADDRESS_FAMILIES.AF_INET;
                sockaddr.sin_port = htons(port);
                sockaddr.sin_addr = ConvertFromIpAddress(address);
                return sockaddr;

            }

            internal static in_addr ConvertFromIpAddressTcp(IPAddress address)
            {
                var inAddr = new in_addr();
                
                inet_pton(ADDRESS_FAMILIES.AF_INET, address.ToString(), ref inAddr);
                /*
                var addressBytes = address.GetAddressBytes();
                inAddr.s_b1 = addressBytes[0];
                inAddr.s_b2 = addressBytes[1];
                inAddr.s_b3 = addressBytes[2];
                inAddr.s_b4 = addressBytes[3];
                */
                return inAddr;
            }

            internal static sockaddr_in ConvertFromIpAddressTcp(IPAddress address, ushort port)
            {
                var sockaddr = new sockaddr_in();
                sockaddr.sin_family = ADDRESS_FAMILIES.AF_INET;
                sockaddr.sin_port = htons(port);
                sockaddr.sin_addr = ConvertFromIpAddressTcp(address);
                return sockaddr;

            }


            [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
            internal static extern IntPtr WSASocket(ADDRESS_FAMILIES af, SOCKET_TYPE socket_type, PROTOCOL protocol, IntPtr lpProtocolInfo, Int32 group, OPTION_FLAGS_PER_SOCKET dwFlags);


            [DllImport("Ws2_32.dll")]
            internal static extern ushort htons(ushort hostshort);


            [DllImport("ws2_32.dll", CharSet = CharSet.Auto)]
            internal static extern Int32 WSAGetLastError();

            [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            internal static extern Int32 WSAStartup(UInt16 wVersionRequested, out WSAData wsaData);

            [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            internal static extern Int32 WSACleanup();

            [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            internal static extern IntPtr socket(ADDRESS_FAMILIES af, SOCKET_TYPE socket_type, PROTOCOL protocol);

            [DllImport("ws2_32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            internal static extern int closesocket(IntPtr s);

            [DllImport("Ws2_32.dll", CharSet = CharSet.Unicode, EntryPoint = "InetPtonW")]
            internal static extern uint inet_pton(ADDRESS_FAMILIES Family, string pszAddrString, ref in_addr pAddrBuf);

            [DllImport("Ws2_32.dll")]
            internal static extern int bind(IntPtr s, ref sockaddr_in addr, int addrsize);

            [DllImport("Ws2_32.dll")]
            internal static extern int connect(IntPtr s, ref sockaddr_in addr, int addrsize);

            [DllImport("ws2_32.dll", SetLastError = true)]
            internal static extern int sendto(IntPtr Socket, IntPtr buff, int len, SendDataFlags flags, ref sockaddr_in To, int tomlen);

            [DllImport("Ws2_32.dll", SetLastError = true)]
            internal static extern int setsockopt(IntPtr s, SocketOptionLevel level, SocketOptionName optname, ref uint optval, int optlen);

            [DllImport("Ws2_32.dll", SetLastError = true)]
            internal static extern int getsockopt(IntPtr s, SocketOptionLevel level, SocketOptionName optname, out int optval, ref int optlen);


            [DllImport("Ws2_32.dll")]
            internal static extern IntPtr WSACreateEvent();

            [DllImport("Ws2_32.dll")]
            internal static extern bool WSACloseEvent(IntPtr hEvent);

            [DllImport("Ws2_32.dll", SetLastError = true)]
            //internal static extern int WSASendTo(IntPtr socket, IntPtr lpBuffers, UInt32 dwBufferCount, out UInt32 lpNumberOfBytesSent, UInt32 dwFlags, ref sockaddr_in lpTo, Int32 iToLen, IntPtr overlapped, IntPtr lpCompletionRoutine);
            //internal static extern int WSASendTo(IntPtr socket, ref WSABUF[] buffer , UInt32 dwBufferCount, out UInt32 lpNumberOfBytesSent, UInt32 dwFlags, ref sockaddr_in lpTo, Int32 iToLen, IntPtr overlapped, IntPtr lpCompletionRoutine);
            internal static extern int WSASendTo(IntPtr socket, WSABUF[] buffer, UInt32 dwBufferCount, out UInt32 lpNumberOfBytesSent, UInt32 dwFlags, ref sockaddr_in lpTo, Int32 iToLen, IntPtr overlapped, IntPtr lpCompletionRoutine);

            [DllImport("Ws2_32.dll", SetLastError = true)]
            internal static extern int WSASend(IntPtr socket, WSABUF[] buffer, UInt32 dwBufferCount, out UInt32 lpNumberOfBytesSent, UInt32 dwFlags, IntPtr overlapped, IntPtr lpCompletionRoutine);

            [DllImport("Ws2_32.dll", SetLastError = true)]
            internal static extern int WSARecv(IntPtr socket, WSABUF[] buffer, UInt32 dwBufferCount, out UInt32 lpNumberOfBytesSent, UInt32 dwFlags, IntPtr overlapped, IntPtr lpCompletionRoutine);

            [DllImport("Ws2_32.dll")]
            internal static extern int WSAWaitForMultipleEvents(UInt32 cEvents, IntPtr lphEvents, bool fWaitAll, UInt32 dwTimeout, bool fAlertable);

            [DllImport("Ws2_32.dll")]
            internal static extern int WSASetUdpSendMessageSize(IntPtr socket, UInt32 MsgSize);



            internal enum OPTION_FLAGS_PER_SOCKET : short
            {
                // turn on debugging info recording  
                SO_DEBUG = 0x0001,
                // socket has had listen()  
                SO_ACCEPTCONN = 0x0002,
                // allow local address reuse  
                SO_REUSEADDR = 0x0004,
                // keep connections alive  
                SO_KEEPALIVE = 0x0008,
                // just use interface addresses  
                SO_DONTROUTE = 0x0010,
                // permit sending of broadcast msgs  
                SO_BROADCAST = 0x0020,
                // bypass hardware when possible  
                SO_USELOOPBACK = 0x0040,
                // linger on close if data present  
                SO_LINGER = 0x0080,
                // leave received OOB data in line  
                SO_OOBINLINE = 0x0100,
                SO_DONTLINGER = (int)(~SO_LINGER),
                // disallow local address reuse
                SO_EXCLUSIVEADDRUSE = ((int)(~SO_REUSEADDR)),

                ///*
                // * Additional options.
                // */
                // send buffer size  
                SO_SNDBUF = 0x1001,
                // receive buffer size  
                SO_RCVBUF = 0x1002,
                // send low-water mark  
                SO_SNDLOWAT = 0x1003,
                // receive low-water mark  
                SO_RCVLOWAT = 0x1004,
                // send timeout  
                SO_SNDTIMEO = 0x1005,
                // receive timeout  
                SO_RCVTIMEO = 0x1006,
                // get error status and clear  
                SO_ERROR = 0x1007,
                // get socket type  
                SO_TYPE = 0x1008,

                ///*
                // * WinSock 2 extension -- new options
                // */
                // ID of a socket group  
                SO_GROUP_ID = 0x2001,
                // the relative priority within a group
                SO_GROUP_PRIORITY = 0x2002,
                // maximum message size  
                SO_MAX_MSG_SIZE = 0x2003,
                // WSAPROTOCOL_INFOA structure  
                SO_PROTOCOL_INFOA = 0x2004,
                // WSAPROTOCOL_INFOW structure  
                SO_PROTOCOL_INFOW = 0x2005,
                // configuration info for service provider  
                PVD_CONFIG = 0x3001,
                // enable true conditional accept: connection is not ack-ed to the other side until conditional function returns CF_ACCEPT  
                SO_CONDITIONAL_ACCEPT = 0x3002,
                WSA_FLAG_REGISTERED_IO = 0x100,
                WSA_FLAG_OVERLAPPED = 0x01
            }

            internal enum SocketOptionLevel
            {
                IP = 0,
                IPv6 = 0x29,
                Socket = 0xffff,
                Tcp = 6,
                Udp = 0x11
            }


            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            internal struct WSAData
            {
                internal Int16 version;
                internal Int16 highVersion;

                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] internal String description;

                [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] internal String systemStatus;

                internal Int16 maxSockets;
                internal Int16 maxUdpDg;
                internal IntPtr vendorInfo;
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Size = 16)]
            internal struct WSABUF
            {
                internal UInt32 length;
                internal IntPtr buf;
            }

            internal enum SocketOptionName
            {
                AcceptConnection = 2,
                AddMembership = 12,
                AddSourceMembership = 15,
                BlockSource = 0x11,
                Broadcast = 0x20,
                BsdUrgent = 2,
                ChecksumCoverage = 20,
                Debug = 1,
                DontFragment = 14,
                DontLinger = -129,
                DontRoute = 0x10,
                DropMembership = 13,
                DropSourceMembership = 0x10,
                Error = 0x1007,
                ExclusiveAddressUse = -5,
                Expedited = 2,
                HeaderIncluded = 2,
                HopLimit = 0x15,
                IPOptions = 1,
                IPProtectionLevel = 0x17,
                IpTimeToLive = 4,
                IPv6Only = 0x1b,
                KeepAlive = 8,
                Linger = 0x80,
                MaxConnections = 0x7fffffff,
                MulticastInterface = 9,
                MulticastLoopback = 11,
                MulticastTimeToLive = 10,
                NoChecksum = 1,
                NoDelay = 1,
                OutOfBandInline = 0x100,
                PacketInformation = 0x13,
                ReceiveBuffer = 0x1002,
                ReceiveLowWater = 0x1004,
                ReceiveTimeout = 0x1006,
                ReuseAddress = 4,
                SendBuffer = 0x1001,
                SendLowWater = 0x1003,
                SendTimeout = 0x1005,
                Type = 0x1008,
                TypeOfService = 3,
                UnblockSource = 0x12,
                UpdateAcceptContext = 0x700b,
                UpdateConnectContext = 0x7010,
                UseLoopback = 0x40,
                MsgSegmentSize = 0x300c,
                UDP_SEND_MSG_SIZE = 2
            }

            internal enum ADDRESS_FAMILIES : short
            {
                /// <summary>
                /// Unspecified [value = 0].
                /// </summary>
                AF_UNSPEC = 0,
                /// <summary>
                /// Local to host (pipes, portals) [value = 1].
                /// </summary>
                AF_UNIX = 1,
                /// <summary>
                /// Internetwork: UDP, TCP, etc [value = 2].
                /// </summary>
                AF_INET = 2,
                /// <summary>
                /// Arpanet imp addresses [value = 3].
                /// </summary>
                AF_IMPLINK = 3,
                /// <summary>
                /// Pup protocols: e.g. BSP [value = 4].
                /// </summary>
                AF_PUP = 4,
                /// <summary>
                /// Mit CHAOS protocols [value = 5].
                /// </summary>
                AF_CHAOS = 5,
                /// <summary>
                /// XEROX NS protocols [value = 6].
                /// </summary>
                AF_NS = 6,
                /// <summary>
                /// IPX protocols: IPX, SPX, etc [value = 6].
                /// </summary>
                AF_IPX = 6,
                /// <summary>
                /// ISO protocols [value = 7].
                /// </summary>
                AF_ISO = 7,
                /// <summary>
                /// OSI is ISO [value = 7].
                /// </summary>
                AF_OSI = 7,
                /// <summary>
                /// european computer manufacturers [value = 8].
                /// </summary>
                AF_ECMA = 8,
                /// <summary>
                /// datakit protocols [value = 9].
                /// </summary>
                AF_DATAKIT = 9,
                /// <summary>
                /// CCITT protocols, X.25 etc [value = 10].
                /// </summary>
                AF_CCITT = 10,
                /// <summary>
                /// IBM SNA [value = 11].
                /// </summary>
                AF_SNA = 11,
                /// <summary>
                /// DECnet [value = 12].
                /// </summary>
                AF_DECnet = 12,
                /// <summary>
                /// Direct data link interface [value = 13].
                /// </summary>
                AF_DLI = 13,
                /// <summary>
                /// LAT [value = 14].
                /// </summary>
                AF_LAT = 14,
                /// <summary>
                /// NSC Hyperchannel [value = 15].
                /// </summary>
                AF_HYLINK = 15,
                /// <summary>
                /// AppleTalk [value = 16].
                /// </summary>
                AF_APPLETALK = 16,
                /// <summary>
                /// NetBios-style addresses [value = 17].
                /// </summary>
                AF_NETBIOS = 17,
                /// <summary>
                /// VoiceView [value = 18].
                /// </summary>
                AF_VOICEVIEW = 18,
                /// <summary>
                /// Protocols from Firefox [value = 19].
                /// </summary>
                AF_FIREFOX = 19,
                /// <summary>
                /// Somebody is using this! [value = 20].
                /// </summary>
                AF_UNKNOWN1 = 20,
                /// <summary>
                /// Banyan [value = 21].
                /// </summary>
                AF_BAN = 21,
                /// <summary>
                /// Native ATM Services [value = 22].
                /// </summary>
                AF_ATM = 22,
                /// <summary>
                /// Internetwork Version 6 [value = 23].
                /// </summary>
                AF_INET6 = 23,
                /// <summary>
                /// Microsoft Wolfpack [value = 24].
                /// </summary>
                AF_CLUSTER = 24,
                /// <summary>
                /// IEEE 1284.4 WG AF [value = 25].
                /// </summary>
                AF_12844 = 25,
                /// <summary>
                /// IrDA [value = 26].
                /// </summary>
                AF_IRDA = 26,
                /// <summary>
                /// Network Designers OSI &amp; gateway enabled protocols [value = 28].
                /// </summary>
                AF_NETDES = 28,
                /// <summary>
                /// [value = 29].
                /// </summary>
                AF_TCNPROCESS = 29,
                /// <summary>
                /// [value = 30].
                /// </summary>
                AF_TCNMESSAGE = 30,
                /// <summary>
                /// [value = 31].
                /// </summary>
                AF_ICLFXBM = 31
            }

            internal enum SOCKET_TYPE : short
            {
                /// <summary>
                /// stream socket
                /// </summary>
                SOCK_STREAM = 1,

                /// <summary>
                /// datagram socket
                /// </summary>
                SOCK_DGRAM = 2,
                /// <summary>
                /// raw-protocol interface
                /// </summary>
                SOCK_RAW = 3,
                /// <summary>
                /// reliably-delivered message
                /// </summary>
                SOCK_RDM = 4,
                /// <summary>
                /// sequenced packet stream
                /// </summary>
                SOCK_SEQPACKET = 5
            }

            internal enum PROTOCOL : short
            {
                //dummy for IP  
                IPPROTO_IP = 0,
                //control message protocol  
                IPPROTO_ICMP = 1,
                //internet group management protocol  
                IPPROTO_IGMP = 2,
                //gateway^2 (deprecated)  
                IPPROTO_GGP = 3,
                //tcp  
                IPPROTO_TCP = 6,
                //pup  
                IPPROTO_PUP = 12,
                //user datagram protocol  
                IPPROTO_UDP = 17,
                //xns idp  
                IPPROTO_IDP = 22,
                //IPv6  
                IPPROTO_IPV6 = 41,
                //UNOFFICIAL net disk proto  
                IPPROTO_ND = 77,

                /// <summary>
                /// sequenced packet stream
                /// </summary>
                SOCK_SEQPACKET = 5
            }



            [Flags]
            internal enum SendDataFlags
            {
                /// <summary></summary>
                None = 0,
                /// <summary>    Specifies that the data should not be subject to routing. A Windows Sockets service provider can choose to ignore this flag</summary>
                DontRoute = 1,
                /// <summary>Sends OOB data (stream-style socket such as SOCK_STREAM only)</summary>
                OOB = 2
            }

            [StructLayout(LayoutKind.Explicit, Size = 4)]
            internal struct in_addr
            {
                [FieldOffset(0)] internal byte s_b1;
                [FieldOffset(1)] internal byte s_b2;
                [FieldOffset(2)] internal byte s_b3;
                [FieldOffset(3)] internal byte s_b4;

                [FieldOffset(0)] internal ushort s_w1;
                [FieldOffset(2)] internal ushort s_w2;

                [FieldOffset(0)] internal uint S_addr;

                /// <summary>
                /// can be used for most tcp & ip code
                /// </summary>
                internal uint s_addr
                {
                    get { return S_addr; }
                }

                /// <summary>
                /// host on imp
                /// </summary>
                internal byte s_host
                {
                    get { return s_b2; }
                }

                /// <summary>
                /// network
                /// </summary>
                internal byte s_net
                {
                    get { return s_b1; }
                }

                /// <summary>
                /// imp
                /// </summary>
                internal ushort s_imp
                {
                    get { return s_w2; }
                }

                /// <summary>
                /// imp #
                /// </summary>
                internal byte s_impno
                {
                    get { return s_b4; }
                }

                /// <summary>
                /// logical host
                /// </summary>
                internal byte s_lh
                {
                    get { return s_b3; }
                }
            }


            [StructLayout(LayoutKind.Sequential)]
            internal struct sockaddr_in
            {
                internal ADDRESS_FAMILIES sin_family;
                internal ushort sin_port;
                internal in_addr sin_addr;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
                internal byte[] sin_zero;
            }
        }
"@ -Language CSharp
    Switch($Protocol){
        'UDP' {
            [Program]::UdpSender($Source, $Destination, $BufferLength, $PacketCount, $Iterations)
        }
        'TCP' {
            [Program]::TcpSender($Source, $Destination, $BufferLength, $PacketCount, $Iterations)
        }
    }    
}