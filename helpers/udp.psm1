# This test requires the admin to have a DPDK enabled Linux VM setup that has pktgen installed.
# The VM must be able to connect to each node that will be tested, and should have each node able to ssh to the VM without using a password.
# The test will fail if a password is required to connect to the VM.  

function Invoke-UDPBlast {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [PSObject] $Server,

        [Parameter(Mandatory=$true, Position=1)]
        [PSObject] $DpdkUser,

        [Parameter(Mandatory=$true, Position=2)]
        [PSObject] $DpdkIp
    )

    $UDPBlastResults = New-Object -TypeName psobject

    $ServerCounter += Start-Job -ScriptBlock {
        param ([string] $Server)
        $paths = (Get-Counter -ListSet UDPv4).paths
        Get-Counter -ComputerName $Server.NodeName -Counter $paths -MaxSamples 20
    } -ArgumentList $Server

    $ServerOutput += Start-Job -ScriptBlock {
        param ([string] $Server, [string] $DpdkIp, [string] $DpdkUser)

        Invoke-Command -Computername $Server -ScriptBlock {
            param ([string] $Server, [string] $DpdkIp, [string] $DpdkUser)
            $Command='printf "set all proto udp\nset all size 1518\nset all dst ip $Server.IPAddress\nset all dst mac $Server.MacAddress\nset all dport 8888\n start all\ndelay 50000\nstop all\nquit" > /home/b/test.pkt.sequences.test && pktgen -l 1-2 -- -P -m "2.1" -f /home/b/test.pkt.sequences.test'
            ssh $DpdkUser@$DpdkIp $Command
        } -ArgumentList $Server,$ServerIP,$DpdkUser
    } -ArgumentList $Server,$DpdkIp,$DpdkUser

    $j++

    $RawData = New-Object -TypeName psobject
    $RawData | Add-Member -MemberType NoteProperty -Name ServerBytesPerSecond -Value $ServerBpsArray
    $RawData | Add-Member -MemberType NoteProperty -Name MinLinkSpeedBps -Value $MinAcceptableLinkSpeedBps

    $UDPBlastResults | Add-Member -MemberType NoteProperty -Name RxGbps -Value $ServerGbpsArray
    $UDPBlastResults | Add-Member -MemberType NoteProperty -Name ServerSuccess -Value $ServerSuccess
    $UDPBlastResults | Add-Member -MemberType NoteProperty -Name RawData -Value $RawData

    Return $UDPBlastResults
}