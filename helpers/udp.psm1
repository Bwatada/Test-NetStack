function Invoke-UDPBlast {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [PSObject] $Server,

        [Parameter(Mandatory=$true, Position=1)]
        [PSObject] $ClientNetwork
    )

    $UDPBlastResults = New-Object -TypeName psobject
    $ClientNetworksTested = @()
    $NClientResults = @()
    $ResultString = ""
    $ExpectedTPUTDec = $ExpectedTPUT / 100

    $j = 9000

    $ServerOutput = @()
    $ClientOutput = @()
    $ServerCounter = @()
    $ClientCounter = @()
    $ServerSuccess = $True
    $MultiClientSuccess = $True

    $ClientNetwork | ForEach-Object {
        $ClientName = $_.NodeName
        $ClientIP = $_.IPAddress
        $ClientIF = $_.InterfaceIndex
        $ClientInterfaceDescription = $_.InterfaceDescription
        $ClientLinkSpeedBps = [Int]::Parse($_.LinkSpeed.Split()[0]) * [Math]::Pow(10, 9) / 8
        $ServerLinkSpeedBps = [Int]::Parse($Server.LinkSpeed.Split()[0]) * [Math]::Pow(10, 9) / 8

        $ServerCounter += Start-Job -ScriptBlock {
            param ([string] $ServerName, [string] $ServerInterfaceDescription)

            Get-Counter -ComputerName $ServerName -Counter "\RDMA Activity($ServerInterfaceDescription)\RDMA Inbound Bytes/sec" -MaxSamples 20 #-ErrorAction Ignore
        } -ArgumentList $Server.NodeName,$Server.InterfaceDescription

        $ServerOutput += Start-Job -ScriptBlock {
            param ([string] $ServerName, [string] $ServerIP, [string] $ServerIF, [int]$j)
            Invoke-Command -ComputerName $ServerName -ScriptBlock {
                param([string]$ServerIP,[string]$ServerIF,[int]$j)
                cmd /c "NdkPerfCmd.exe -S -ServerAddr $($ServerIP):$j  -ServerIf $ServerIF -TestType rperf -W 20 2>&1"
            } -ArgumentList $ServerIP, $ServerIF, $j
        } -ArgumentList $Server.NodeName, $Server.IPAddress, $Server.InterfaceIndex, $j

        $ClientCounter += Start-Job -ScriptBlock {
            param ([string] $ClientName, [string] $ClientInterfaceDescription)

            Get-Counter -ComputerName $ClientName -Counter "\RDMA Activity($ClientInterfaceDescription)\RDMA Outbound Bytes/sec" -MaxSamples 20
        } -ArgumentList $ClientName,$ClientInterfaceDescription

        $ClientOutput += Start-Job -ScriptBlock {
            param ([string] $ClientName, [string] $ServerIP, [string] $ClientIP, [string] $ClientIF, [int]$j)

            Invoke-Command -Computername $ClientName -ScriptBlock {
                param ([string] $ServerIP, [string] $ClientIP, [string] $ClientIF, [int] $j)
                cmd /c "NdkPerfCmd.exe -C -ServerAddr  $($ServerIP):$j -ClientAddr $($ClientIP) -ClientIf $($ClientIF) -TestType rperf 2>&1"
            } -ArgumentList $ServerIP,$ClientIP,$ClientIF,$j
        } -ArgumentList $ClientName,$Server.IPAddress,$ClientIP,$ClientIF,$j

        $j++
    }

    $ServerBytesPerSecond = 0
    $ServerBpsArray = @()
    $ServerGbpsArray = @()
    $MinAcceptableLinkSpeedBps = ($ServerLinkSpeedBps, $ClientLinkSpeedBps | Measure-Object -Minimum).Minimum * $ExpectedTPUTDec
    $ServerCounter | ForEach-Object {
        $read = Receive-Job $_ -Wait -AutoRemoveJob

        if ($read.Readings) {
            $FlatServerOutput = $read.Readings.split(":") | ForEach-Object {
                try {[uint64]($_)} catch{}
            }
        }

        $ServerBytesPerSecond = ($FlatServerOutput | Measure-Object -Maximum).Maximum
        $ServerBpsArray += $ServerBytesPerSecond
        $ServerGbpsArray += [Math]::Round(($ServerBytesPerSecond * 8) * [Math]::Pow(10, -9), 2)
        $ServerSuccess = $ServerSuccess -and ($ServerBytesPerSecond -gt $MinAcceptableLinkSpeedBps)
    }

    $RawData = New-Object -TypeName psobject
    $RawData | Add-Member -MemberType NoteProperty -Name ServerBytesPerSecond -Value $ServerBpsArray
    $RawData | Add-Member -MemberType NoteProperty -Name MinLinkSpeedBps -Value $MinAcceptableLinkSpeedBps

    $ReceiverLinkSpeedGbps = [Math]::Round(($ServerLinkSpeedBps * 8) * [Math]::Pow(10, -9), 2)

    $UDPBlastResults | Add-Member -MemberType NoteProperty -Name ReceiverLinkSpeedGbps -Value $ReceiverLinkSpeedGbps
    $UDPBlastResults | Add-Member -MemberType NoteProperty -Name RxGbps -Value $ServerGbpsArray
    $UDPBlastResults | Add-Member -MemberType NoteProperty -Name ClientNetworkTested -Value $ClientNetwork.IPAddress
    $UDPBlastResults | Add-Member -MemberType NoteProperty -Name ServerSuccess -Value $ServerSuccess
    $UDPBlastResults | Add-Member -MemberType NoteProperty -Name RawData -Value $RawData

    Return $UDPBlastResults
}