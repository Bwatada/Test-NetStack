
$id = get-random
Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        using System.Text;
        using System.Net;
	using System.Net.Sockets;

        public class Program
        {
		public static void UdpReceive()
		{
	    		//Creates a UdpClient for reading incoming data.
 			UdpClient receivingUdpClient = new UdpClient(8888);

 			//Creates an IPEndPoint to record the IP Address and port number of the sender.
			// The IPEndPoint will allow you to read datagrams sent from any source.
 			IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 8888);
			while (true) {
 				try{
     					// Blocks until a message returns on this socket from a remote host.
     					Byte[] receiveBytes = receivingUdpClient.Receive(ref RemoteIpEndPoint);

	     				Console.WriteLine("This message was sent from " +
     	                                RemoteIpEndPoint.Address.ToString() +
             	                        " on their port number " +
                                	RemoteIpEndPoint.Port.ToString());
 				}
 			catch ( Exception e ){
     				Console.WriteLine(e.ToString());
 			}
			}
		}
        }
"@ -Language CSharp
[Program]::UdpReceive()