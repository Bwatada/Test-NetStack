Function UdpTest {

    [cmdletbinding()]
    param()

    $id = get-random
    Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        using System.Text;
        using System.Net;

        public static class Program
        {
	    public static string UdpReceive()
	    {
		//Client uses as receive udp client
		UdpClient Client = new UdpClient(8888);

		try
		{
     		    Client.BeginReceive(new AsyncCallback(recv), null);
		}
		    catch(Exception e)
		{
   		    MessageBox.Show(e.ToString());
		}

		//CallBack
		private void recv(IAsyncResult res)
		{
    		    IPEndPoint RemoteIpEndPoint = new IPEndPoint(IPAddress.Any, 8888);
    		    byte[] received = Client.EndReceive(res, ref RemoteIpEndPoint);

    		    Client.BeginReceive(new AsyncCallback(recv), null);
		}
            }
        }
"@ -Language CSharp
    [Program]::UdpReceive()
}