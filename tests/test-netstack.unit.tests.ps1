########################################################################
# Test-NetStack Network and Result Data Structures
########################################################################

class InterfaceData {
    [String]$Name
    [String]$SubNet
    [String]$IpAddress
    [String]$IfIndex
    [String]$Description
    [String]$RdmaImplementation
    [String]$vSwitch
    [String]$vSwitchDescription
    [String]$pSwitch
    [Int]$SubnetMask
    [Int]$Vlan
    [Long]$LinkSpeed
    [Boolean]$RdmaEnabled = $false
    [Boolean]$Status = $false
    [HashTable]$SubNetMembers = @{}
    [HashTable]$ConnectionMTU = @{}
}

class NodeNetworkData {
    [String]$Name
    [String]$RdmaProtocol
    [boolean]$IsRDMACapable
    [PSobject[]]$RdmaNetworkAdapters = @()
    [HashTable]$InterfaceListStruct = @{}
}

class SubnetTuple {
    [String]$MachineName
    [String]$IpAddress
}

class ResultInformationData {
    [String]$SourceMachine
    [String]$TargetMachine
    [String]$SourceIp
    [String]$TargetIp
    [Boolean]$Success
    [Int]$RecieveBps
    [Int]$SendBps
}

########################################################################
# Helper Functions
########################################################################
function ConvertTo-IPv4MaskString {

    param(
      [Parameter(Mandatory = $true)]
      [ValidateRange(0, 32)]
      [Int] $MaskBits
    )
    $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))
    $bytes = [BitConverter]::GetBytes([UInt32] $mask)
    (($bytes.Count - 1)..0 | ForEach-Object { [String] $bytes[$_] }) -join "."

}

function Connect-Network {

    param(
      [Parameter(Mandatory = $true)]
      [NodeNetworkData[]] $NetworkData,
      [Parameter(Mandatory = $true)]
      [HashTable] $TestSubNetworks
    )

    $NetworkConnectivityTemp = @{}

    $NetworkData | ForEach-Object {
        
        $hostName = $_.Name

        $_.InterfaceListStruct.Values | ForEach-Object {

            if ($_.Status -eq $true) {

                $MaskVlanTuple = "$($_.Subnet), $($_.VLAN)" 
                $SubnetTuple = [SubnetTuple]::new()
                $SubnetTuple.IpAddress = $_.IpAddress
                $SubnetTuple.MachineName = $hostName
                $NetworkConnectivityTemp[$MaskVlanTuple] +=  @($SubnetTuple)
                $TestSubNetworks[$MaskVlanTuple] += @("$($_.IpAddress)")
            }
            if ($_.VLAN -ne 0) {
                
            }

        }
        
    }

    $NetworkData | ForEach-Object {
        
        $_.InterfaceListStruct.Values | ForEach-Object {
            
            $MaskVlanTuple = "$($_.Subnet), $($_.VLAN)"

            if ($_.IpAddress -ne "" -and $_.IpAddress -notlike $NetworkConnectivityTemp[$MaskVlanTuple].IpAdress) {
                
                $MaskVlanTuple = "$($_.Subnet), $($_.VLAN)"

                $_.SubNetMembers[$_.IpAddress] = $NetworkConnectivityTemp[$MaskVlanTuple]
            }

        }
        
    }

    Write-Host (ConvertTo-Json $NetworkConnectivityTemp)

}

########################################################################
# Test-NetStack Result Walker Functions For Recommendation Functionality 
#####################################################################

# Inbound connectivity and functionality check for a given NIC (with outlier checks).
# This test outputs whether or not TARGET machines succeed.

function Assert-InboundOutboundInterfaceSuccess {

    param(
      [Parameter(Mandatory = $true)]
      [HashTable] $ResultInformationList,
      [Parameter(Mandatory = $true)]
      [String] $StageString
    )

    switch([String]$StageString) {
        
        ("STAGE 1: PING") {

            $ResultData = $ResultInformationList[$StageString]
            $InterfaceList = @()
            $MachineList = @()

            $OutlierInboundRecommendations = @{}
            $OutlierOutboundRecommendations = @{}
            $InterfaceInboundRecommendations = ""
            $InterfaceOutboundRecommendations = ""
            $MachineInboundRecommendations = ""
            $MachineOutboundRecommendations = ""
            $InterfaceInboundSuccesses = @{}
            $InterfaceOutboundSuccesses = @{}
            $MachineInboundSuccesses = @{}
            $MachineOutboundSuccesses = @{}

            $ResultData | ForEach-Object {

                $SourceMachine = $_.SourceMachine
                $TargetMachine = $_.TargetMachine
                $SourceIp = $_.SourceIp
                $TargetIp = $_.TargetIp
                $Success = $_.Success
                
                $InterfaceList += $SourceIp
                $MachineList += $SourceMachine

                $OutlierInboundRecommendations[$TargetIp] += "INDIVIDUAL FAILURE: Ping Failed From Source ($SourceIP) On Machine ($SourceMachine) To Target ($TargetIP).`r`n`tRECOMMENDATION: Verify Subnet And VLAN Settings For Relevant NICs.`r`n"
                $OutlierOutboundRecommendations[$SourceIp] += "INDIVIDUAL FAILURE: Ping Failed From Source ($SourceIP) On Machine ($SourceMachine) To Target ($TargetIP).`r`n`tRECOMMENDATION: Verify Subnet And VLAN Settings For Relevant NICs.`r`n"
                $InterfaceInboundSuccesses[$TargetIp] += @($Success)
                $InterfaceOutboundSuccesses[$SourceIp] += @($Success)
                $MachineInboundSuccesses[$TargetMachine] += @($Success)
                $MachineOutboundSuccesses[$SourceMachine] += @($Success)
            }

            # Write-Host (ConvertTo-Json $InterfaceInboundSuccesses)

            $InterfaceList | ForEach-Object {
                
                $InterfaceInboundSuccess = $InterfaceInboundSuccesses[$_]
                $InterfaceOutboundSuccess = $InterfaceOutboundSuccesses[$_]

                # INBOUND
                if (-not ($InterfaceInboundSuccess -eq $true)) {
                    # Add Interface-Wide Failure Rec
                    $InterfaceInboundRecommendations += "INTERFACE FAILURE: Ping Failed Across All Source NICs for Target NIC ($_).`r`n`tRECOMMENDATION: Verify subnet and VLAN settings for relevant NICs. If the problem persists, consider checking NIC cabling.`r`n"
                } elseif (-not ($InterfaceInboundSuccess -eq $false)) {
                    $InterfaceInboundRecommendations += "INTERFACE Success: Ping Success Across All Source NICs for Target NIC ($_).`r`n`tRECOMMENDATION: DO NOTHING`r`n"
                } else {
                    # Add Individual Failure Rec
                    $InterfaceInboundRecommendations += $OutlierInboundRecommendations[$_]
                }
                

                # OUTBOUND
                if (-not ($InterfaceOutboundSuccess -eq $true)) {
                    # Add Interface-Wide Failure Rec
                    $InterfaceOutboundRecommendations += "INTERFACE FAILURE: Ping Failed Across All Target NICs for Source NIC ($_).`r`n`tRECOMMENDATION: Verify subnet and VLAN settings for relevant NICs. If the problem persists, consider checking NIC cabling.`r`n"

                } elseif (-not ($InterfaceOutboundSuccess -eq $false)) {
                    $InterfaceOutboundRecommendations += "INTERFACE Success: Ping Success Across All Target NICs for Source NIC ($_).`r`n`tRECOMMENDATION: DO NOTHING`r`n"
                } else {
                    # Add Individual Failure Rec
                    $InterfaceOutboundRecommendations += $OutlierInboundRecommendations[$_]
                }
                
            }

            $MachineList | ForEach-Object {

                $MachineInboundSuccess = $MachineInboundSuccesses[$_]
                $MachineOutboundSuccess = $MachineOutboundSuccesses[$_]

                # INBOUND
                if (-not ($MachineInboundSuccess -eq $true)) {
                    # Add Machine-Wide Failure Rec
                    $MachineInboundRecommendations += "MACHINE FAILURE: Ping Failed Across All Source Machines for Target Machine ($_).`r`n`tRECOMMENDATION: Verify firewall settings for the erring machine. If the problem persists, consider checking Machine cabling.`r`n"
                } elseif (-not ($MachineInboundSuccess -eq $false)) {
                    $MachineInboundRecommendations += "MACHINE SUCCESS: Ping Success Across All Source Machines for Target Machine ($_).`r`n`tRECOMMENDATION: DO NOTHING`r`n"
                } else {
                    # Add Individual Failure Rec
                    $MachineInboundRecommendations += $OutlierInboundRecommendations[$_]
                }
                

                # OUTBOUND
                if (-not ($MachineOutboundSuccess -eq $true)) {
                    # Add Machine-Wide Failure Rec
                    $MachineOutboundRecommendations += "MACHINE FAILURE: Ping Failed Across All Target Machines for Source Machine ($_).`r`n`tRECOMMENDATION: Verify firewall settings for the erring machine. If the problem persists, consider checking Machine cabling.`r`n"

                } elseif (-not ($MachineOutboundSuccess -eq $false)) {
                    $MachineOutboundRecommendations += "MACHINE SUCCESS: Ping Success Across All Target Machines for Source Machine ($_).`r`n`tRECOMMENDATION: DO NOTHING`r`n"
                } else {
                    # Add Individual Failure Rec
                    $MachineOutboundRecommendations += $OutlierInboundRecommendations[$_]
                }
                
            }
            
            Write-Host $InterfaceInboundRecommendations
            Write-Host $InterfaceOutboundRecommendations
            Write-Host $MachineInboundRecommendations
            Write-Host $MachineOutboundRecommendations
        }
    }

}

########################################################################
# Begin Pester Test and Network Imaging
########################################################################

Describe "Test Network Stack`r`n" {
    
    [NodeNetworkData[]]$TestNetwork = [NodeNetworkData[]]@();
    [String[]]$MachineCluster = @()
    [HashTable]$TestSubNetworks = @{}
    [HashTable] $Results = @{}
    [HashTable] $Failures = @{}

    [HashTable]$ResultInformationList = @{}
    # $ResultInformationList = @()
    # $StageThreeInformationList = @()
    # $StageFourInformationList = @()
    # $StageFiveInformationList = @()
    # $StageSixInformationList = @()

    Write-Host "Generating Test-NetStack-Output.txt"
    New-Item C:\Test-NetStack\Test-NetStack-Output.txt -ErrorAction SilentlyContinue
    $OutputFile = "Test-NetStack Output File"
    $OutputFile | Set-Content 'C:\Test-NetStack\Test-NetStack-Output.txt'

    $startTime = Get-Date -format:'MM-dd-yyyy HH:mm:ss'

    Write-Host "Starting Test-NetStack: $startTime`r`n"
    "Starting Test-NetStack: $startTime`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

    #TODO: Why are we declaring this since it's already available with $env:ComputerName?
    $machineName = $env:computername
    $sddcFlag = $false

    if (-not ($MachineList)) {
        try {
            
            Write-Host "VERBOSE: No list of machines passed to Test-NetStack. Assuming machine running in cluster.`r`n"
            "VERBOSE: No list of machines passed to Test-NetStack. Assuming machine running in cluster.`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

            $MachineCluster = Get-ClusterNode
        
        } catch {
            
            #TODO: Exit will actually close the window if running in the shell. We should Write-Error to the screen.
            Write-Host "VERBOSE: An error has occurred. Machine $($machineName) is not running the cluster service. Exiting Test-NetStack.`r`n"
            "VERBOSE: An error has occurred. Machine $($machineName) is not running the cluster service. Exiting Test-NetStack.`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
            Exit
        
        }
    }
    Else {
        $MachineCluster = $MachineList
    }

    Write-Host "The Following List of Machines will be tested: $MachineCluster`r`n"
    "The Following List of Machines will be tested: $MachineCluster`r`n"| Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

    $equalRdmaProtocol = $false
    $rdmaProtocol = ""

    ########################################################################
    # Compute Network Construction and RDMA Capability
    ########################################################################

    Write-Host "Identifying Network.`r`n"
    "Beginning Network Construction.`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

    $MachineCluster | ForEach-Object {
                
        $newNode = [NodeNetworkData]::new()
        
        $newNode.Name = $_

        $newNode.RdmaNetworkAdapters = Get-NetAdapterRdma -CimSession $newNode.Name | Select Name, InterfaceDescription, Enabled

        # $vmTeamMapping = Get-VMNetworkAdapterTeamMapping -ManagementOS

        Write-Host "Machine Name: $($newNode.Name)`r`n"
        "Machine Name: $($newNode.Name)`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        
        (Get-NetAdapter -CimSession $_) | ForEach-Object {

            $newInterface = [InterfaceData]::new()

            $newInterface.Name = $_.Name
            $newInterface.Description = $_.InterfaceDescription
            $newInterface.IfIndex = $_.ifIndex
            $newInterface.IpAddress = (Get-NetIpAddress -CimSession $newNode.Name | where InterfaceIndex -eq $_.ifIndex | where AddressFamily -eq "IPv4" | where SkipAsSource -Like "*False*").IpAddress
            $newInterface.Status = If ($_.Status -match "Up" -and $newInterface.IpAddress -ne "") {$true} Else {$false}
            $newInterface.SubnetMask = (Get-NetIpAddress -CimSession $newNode.Name | where InterfaceIndex -eq $_.ifIndex | where AddressFamily -eq "IPv4" | where SkipAsSource -Like "*False*").PrefixLength
            
            $LinkSpeed = $_.LinkSpeed.split(" ")
            Switch($LinkSpeed[1]) {
                
                ("Gbps") {$newInterface.LinkSpeed = [Int]::Parse($LinkSpeed[0]) * [Math]::Pow(10, 9)}

                ("Mbps") {$newInterface.LinkSpeed = [Int]::Parse($LinkSpeed[0]) * [Math]::Pow(10, 6)}

                ("bps") {$newInterface.LinkSpeed = [Int]::Parse($LinkSpeed[0]) * [Math]::Pow(10, 3)}

            }
            Write-Host ".`r`n"

            if ($newInterface.IpAddress -ne "") {
                
                $subnet = [IPAddress] (([IPAddress] $newInterface.IpAddress).Address -band ([IPAddress] (ConvertTo-IPv4MaskString $newInterface.SubnetMask)).Address)
                
                $newInterface.Subnet =  "$($subnet) / $($newInterface.SubnetMask)"
            }
            
            $newInterface.VLAN = (Get-VMNetworkAdapterIsolation -ManagementOS -CimSession $newNode.Name | where ParentAdapter -like "*$($_.Name)*").DefaultIsolationID

            if ($newInterface.VLAN -eq "") {
                
                $newInterface.VLAN = (Get-NetAdapterAdvancedProperty -CimSession $newNode.Name | where Name -like "$($_.Name)" | where DisplayName -like "VLAN ID").DisplayValue

            }

            if ($newInterface.Description -like "*Mellanox*") {

                $newInterface.RdmaImplementation = "RoCE"
                
            } else { 

                try {

                    $newInterface.RdmaImplementation = (Get-NetAdapterAdvancedProperty -CimSession $newNode.Name -Name $_.Name -RegistryKeyword *NetworkDirectTechnology -ErrorAction Stop).RegistryValue
                
                    switch([Int]$rdmaProtocol) {
            
                        0 {$newInterface.RdmaImplementation = "N/A"}
                        
                        1 {$newInterface.RdmaImplementation = "iWARP"}
                        
                        2 {$newInterface.RdmaImplementation = "InfiniBand"}
                        
                        3 {$newInterface.RdmaImplementation = "RoCE"}

                        4 {$newInterface.RdmaImplementation = "RoCEv2"}
                    
                    }

                } catch {

                    $newInterface.RdmaImplementation = "N/A"

                }

            }

            $newInterface.RdmaEnabled = $newInterface.Name -In ($newNode.RdmaNetworkAdapters | where Enabled -Like "True").Name
        
            $newNode.InterfaceListStruct.add($newInterface.Name, $newInterface)
        }

        if ((Get-NetAdapterRdma).count -ne 0) {

            $newNode.IsRDMACapable = $true

        } else {

            Write-Host "VERBOSE: Machine $($newNode.Name) is not RDMA capable.`r`n"
            "VERBOSE: Machine $($newNode.Name) is not RDMA capable.`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

        }
        
        $rdmaEnabledNics = (Get-NetAdapterRdma -CimSession $newNode.Name | Where-Object Enabled -eq $true).Name
        Write-Host "VERBOSE: RDMA Adapters"
        "VERBOSE: RDMA Adapters" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
        Write-Host ($rdmaEnabledNics )
        $rdmaEnabledNics | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
        Write-Host "`r`n"
        "`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 

        # If it's QLogic, iWARP, if it's Mellanox, Roce
        # Chelsio can be either

        ########################################################################
        ## SDDC Machines, checking config for protocol rocki v. iwarp
        ########################################################################
    
        if ($sddcFlag) {    

            Write-Host "VERBOSE: SDDC Machine, checking IpAssignment.json for RDMA Protocol.`r`n"
            "VERBOSE: SDDC Machine, checking IpAssignment.json for RDMA Protocol.`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            
            $sdnNetworkResourceFileRelative = "\E2EWorkload\IpAssignment.json"
            $sdnNetworkResourceFile = "\\$($newNode.Name)\C$\" + $sdnNetworkResourceFileRelative 

            if([System.IO.File]::Exists($sdnNetworkResourceFile))
            {   
                $payload = get-content -Path $sdnNetworkResourceFile -raw
                $config = convertfrom-json $payload

            } else {
                
                Write-Host "VERBOSE: SDDC Machine does not have access to IpAssignment.json. Exiting.`r`n"
                "VERBOSE: SDDC Machine does not have access to IpAssignment.json. Exiting.`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
                Exit

            }

            if ($newNode.Name -eq $machineName) {

                $equalRdmaProtocol = $true
                $rdmaProtocol = $config.Payload.RdmaMode

            } else {

                $equalRdmaProtocol = $config.Payload.RdmaMode -eq $rdmaProtocol

            }

        } elseif ($newNode.Description -like "*Mellanox*") {

            $newNode.RdmaProtocol = "RoCE"
            
        } 
        
        $newNode.IsRDMACapable = $equalRdmaProtocol
        
        $TestNetwork += $newNode
    }

    Connect-Network -NetworkData $TestNetwork -TestSubNetworks $TestSubNetworks

    Write-Host "####################################`r`n"
    Write-Host "VERBOSE: BEGINNING Test-NetStack CORE STAGES`r`n"
    Write-Host "####################################`r`n"
    "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
    "VERBOSE: BEGINNING Test-NetStack CORE STAGES`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
    "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 

    Write-Host "# The Following Subnetworks Will Be Tested"
    Write-Host "# Calculated According To Subnet and VLAN Configurations`r`n"
    "# The Following Subnetworks Will Be Tested" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
    "# Calculated According To Subnet and VLAN Configurations`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 

    Write-Host (ConvertTo-Json $TestSubNetworks)
    
    ####################################
    # BEGIN Test-NetStack CONGESTION
    ####################################
        
    ####################################
    # Test Machines for PING Capability
    ####################################
    if ($StageNumber -ge 1) {
        
        Context "Basic Connectivity (ping)`r`n" {

            Write-Host "####################################`r`n"
            Write-Host "VERBOSE: Testing Connectivity Stage 1: PING`r`n"
            Write-Host "####################################`r`n"
            "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "VERBOSE: Testing Connectivity Stage 1: PING`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 

            $Results["STAGE 1: PING"] = @("| SOURCE MACHINE`t| SOURCE NIC`t`t| TARGET NIC`t`t| CONNECTIVITY`t|")
            $Failures["STAGE 1: PING"] = @("| SOURCE MACHINE`t| SOURCE NIC`t`t| TARGET NIC`t`t| CONNECTIVITY`t|")
            $ResultInformationList["STAGE 1: PING"] = [ResultInformationData[]]@()
            

            $TestNetwork | ForEach-Object {
                
                Write-Host "VERBOSE: Testing Ping Connectivity on Machine: $($_.Name)`r`n"
                "VERBOSE: Testing Ping Connectivity on Machine: $($_.Name)`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                
                $hostName = $_.Name
                $ValidInterfaceList = $_.InterfaceListStruct.Values | where IPAddress -ne "" 

                $ValidInterfaceList | ForEach-Object {
                    
                    $SourceStatus = $_.Status

                    if ($SourceStatus) {
                        
                        Write-Host "VERBOSE: Testing Ping Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n"
                        "VERBOSE: Testing Ping Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        
                        $SubNetTable = $_.SubNetMembers
                        $SourceIp = $SubNetTable.Keys[0]
                        $PeerNetList = $SubNetTable[$SourceIp] | where $_.IpAddress -notlike $SourceIp
                        
                        # $IndividualRecommendations = @()

                        $PeerNetList | ForEach-Object {

                            $NewResultInformation = [ResultInformationData]::new()
                            $TargetName = $_.MachineName
                            $TargetIP = $_.IpAddress

                            $Success = $false
                            if ($SourceIp -NotLike $TargetIp -and $SourceStatus) {
                                
                                It "Basic Connectivity (ping) -- Verify Basic Connectivity: Between $($TargetIP) and $($SourceIP))" {
                                    
                                    Write-Host "ping $($TargetIP) -S $($SourceIP)`r`n"
                                    "ping $($TargetIP) -S $($SourceIP)`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        
                                    $Output = Invoke-Command -Computername $hostName -ScriptBlock { cmd /c "ping $Using:TargetIP -S $Using:SourceIP" } | findstr /R "Ping Packets"

                                    $Success = "$Output" -match "(0% Loss)"
                                    # $InterfaceSuccess += $Success

                                    "PING STATUS SUCCESS: $Success`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                    
                                    $Results["STAGE 1: PING"] += "| ($hostName)`t`t| ($SourceIP)`t| ($TargetIP)`t| $Success`t`t|"

                                    if (-not $Success) {
                                        $Failures["STAGE 1: PING"] += "| ($hostName)`t`t| ($SourceIP)`t| ($TargetIP)`t| $Success`t`t|"
                                        # $IndividualRecommendations += "INDIVIDUAL FAILURE: Ping Failed From Source ($SourceIP) To Target ($TargetIP)."
                                        # $IndividualRecommendations += "`tRECOMMENDATION: Verify Subnet And VLAN Settings For Relevant NICs."
                                    }

                                    $NewResultInformation.SourceMachine = $hostName
                                    $NewResultInformation.TargetMachine = $TargetName
                                    $NewResultInformation.SourceIp = $SourceIp
                                    $NewResultInformation.TargetIp = $TargetIp
                                    $NewResultInformation.Success = $Success
                                    $ResultInformationList["STAGE 1: PING"] += $NewResultInformation

                                    $Success | Should Be $True
                                }

                                Write-Host "`r`n####################################`r`n"
                                "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                            } 
                        }
                        
                        # if ($InterfaceSuccess) {
                        #     $PingRecommendations += $IndividualRecommendations
                        # } else {
                        #     $InterfaceRecommendations += "INTERFACE FAILURE: Ping Failed Across All Targets on NIC ($SourceName)."
                        #     $InterfaceRecommendations += "`tRECOMMENDATION: Verify subnet and VLAN settings for relevant NICs. If the problem persists, consider checking NIC cabling."
                        # }

                        # $MachineSuccess += $InterfaceSuccess

                    }
                }
                # if ($MachineSuccess.Count | where ) {
                #     $PingRecommendations += $InterfaceRecommendations
                # } else {
                #     $PingRecommendations += "Machine FAILURE: Ping Failed Across All NICs on Machine ($hostName)."
                #     $PingRecommendations += "`tRECOMMENDATION: Verify firewall settings on the relevant machine. If the problem persists, consider checking NIC cabling."
                # }
            }
        }
        Write-Host (ConvertTo-Json $ResultInformationList)
        Assert-InboundOutboundInterfaceSuccess -ResultInformationList $ResultInformationList -StageString "STAGE 1: PING"

        Write-Host (ConvertTo-Json $ResultInformationList["STAGE 1: PING"])
        Write-Host "RESULTS Stage 1: PING`r`n"
        "RESULTS Stage 1: PING`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        
        ($Results["STAGE 1: PING"]) | ForEach-Object {

            Write-Host $_ 
            $_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

        }
    }

    # ###################################
    # Test Machines for PING -L -F Capability
    # ###################################
    if ($StageNumber -ge 2) {

        Context "MTU Connectivity Test (Ping -L -F)`r`n" {
            
            Write-Host "####################################`r`n"
            Write-Host "VERBOSE: Testing Connectivity Stage 2: PING -L -F`r`n"
            Write-Host "####################################`r`n"
            "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "VERBOSE: Testing Connectivity Stage 2: PING -L -F`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 

            $Results["STAGE 2: PING -L -F"] = @("| SOURCE MACHINE`t| SOURCE NIC`t`t| TARGET MACHINE`t`t|TARGET NIC`t`t| MTU`t`t| SUCCESS`t|")
            $Failures["STAGE 2: PING -L -F"] = @("| SOURCE MACHINE`t| SOURCE NIC`t`t| TARGET MACHINE`t`t|TARGET NIC`t`t| MTU`t`t|")

            $TestNetwork | ForEach-Object {

                "VERBOSE: Testing Ping -L -F Connectivity on Machine: $($_.Name)" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                $hostName = $_.Name

                $ValidInterfaceList = $_.InterfaceListStruct.Values | where IPAddress -ne "" 

                $ValidInterfaceList | ForEach-Object {
                    
                    $SourceStatus = $_.Status

                    if ($SourceStatus) {

                        Write-Host "VERBOSE: Testing Ping -L -F Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n"
                        "VERBOSE: Testing Ping Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                        
                        $TestInterface = $_

                        $InterfaceName = $TestInterface.Name

                        $InterfaceIfIndex = $TestInterface.IfIndex

                        $SubNetTable = $_.SubNetMembers

                        $SourceIp = $SubNetTable.Keys[0]

                        $PeerNetList = $SubNetTable[$SourceIp] | where $_.IpAddress -notlike $SourceIp 
                        
                        $PeerNetList | ForEach-Object {

                            $TargetIP = $_.IpAddress
                            $TargetMachine = $_.MachineName

                            if ($SourceIp -NotLike $TargetIp) {
                                
                                It "MTU Connectivity -- Verify Connectivity and Discover MTU: Between Target $($TargetIP) and Source $($SourceIP)" {
                                    
                                    $PacketSize = 0
                                    $ReportedMTU
                                    try {
                                        $PacketSize = [Int](Get-NetAdapterAdvancedProperty -CimSession $hostName | where Name -eq $InterfaceName | where DisplayName -eq "Jumbo Packet").RegistryValue[0]
                                        $ReportedMTU = $PacketSize
                                    } catch {
                                        $PacketSize = [Int](Get-NetIPInterface -CimSession $hostName | where ifIndex -eq $InterfaceIfIndex | where AddressFamily -eq "IPv4").nlMtu
                                        $ReportedMTU = $PacketSize
                                    }

                                    if ($PacketSize -eq 1514 -or $PacketSize -eq 9014) {
                                        $PacketSize -= 42
                                    } elseif ($PacketSize -eq 1500 -or $PacketSize -eq 9000) {
                                        $PacketSize -= 28
                                    }

                                    $Success = $False
                                    $Failure = $False

                                    if ($PacketSize -eq 0) {

                                        $PacketSize = 1000
                                        $Success = $True

                                        while($Success) {
                                        
                                            Write-Host "ping $($TargetIP) -S $($SourceIP) -l $PacketSize -f -n 1`r`n"
                                            "ping $($TargetIP) -S $($SourceIP) -l $PacketSize -f -n 1`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                                            $Output = Invoke-Command -Computername $hostName -ScriptBlock { cmd /c "ping $Using:TargetIP -S $Using:SourceIP -l $Using:PacketSize -f -n 1" } | Out-String
                                            $Success = ("$Output" -match "Received = 1")
                                            $Failure = ("$Output" -match "General Failure") -or ("$Output" -match "Destination host unreachable")
                                            $Success = $Success -and -not $Failure
                                            Write-Host "PING STATUS: $(If ($Success) {"SUCCESS"} Else {"FAILURE"}) FOR MTU: $PacketSize`r`n"
                                            "PING STATUS: $(If ($Success) {"SUCCESS"} Else {"FAILURE"}) FOR MTU: $PacketSize`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                            
                                            if ($Success) {
                                                $PacketSize *= 2
                                            } elseif ($Failure) {
                                                Write-Host "PING STATUS: General FAILURE - Host May Be Unreachable`r`n"
                                                "PING STATUS: General FAILURE - Host May Be Unreachable`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                            } else {
                                                Write-Host "Upper Bound of $PacketSize found. Working to find specific value.`r`n"
                                                "Upper Bound of $PacketSize found. Working to find specific value.`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                            }
                                        }
                                    }

                                    while((-not $Success) -and (-not $Failure)) {

                                        Write-Host "ping $($TargetIP) -S $($SourceIP) -l $PacketSize -f -n 1`r`n"
                                        "ping $($TargetIP) -S $($SourceIP) -l $PacketSize -f -n 1`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                                        $Output = Invoke-Command -Computername $hostName -ScriptBlock { cmd /c "ping $Using:TargetIP -S $Using:SourceIP -l $Using:PacketSize -f -n 1" }
                                        $Success = ("$Output" -match "Received = 1")
                                        $Failure = ("$Output" -match "General Failure") -or ("$Output" -match "Destination host unreachable")
                                        $Success = $Success -and -not $Failure

                                        if (-not $Success) {
                                            Write-Host "Attempting to find MTU Estimate. Iterating on 05% MTU decreases.`r`n"
                                            "Attempting to find MTU Estimate. Iterating on 05% MTU decreases.`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                            $PacketSize = [math]::Round($PacketSize - ($PacketSize * .05))
                                        } elseif ($Failure) {
                                            Write-Host "PING STATUS: General FAILURE - Host May Be Unreachable`r`n"
                                            "PING STATUS: General FAILURE - Host May Be Unreachable`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        } else {
                                            Write-Host "PING STATUS: $(If ($Success) {"SUCCESS"} Else {"FAILURE"}). Estimated MTU Found: ~$PacketSize`r`n"
                                            "PING STATUS: $(If ($Success) {"SUCCESS"} Else {"FAILURE"}). Estimated MTU Found: ~$PacketSize`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                            $TestInterface.ConnectionMTU["$TargetIP"] = $PacketSize
                                        }
                                    }
                                    
                                    $ActualMTU = $PacketSize

                                    # VERIFY REPORTED = ~ACTUAL MTU. FAIL IF RANGE > 500 BYTES.
                                    if ([Math]::Abs($ReportedMTU - $ActualMTU) -gt 500) { 
                                        $Success = $False   
                                    }
                                    $Results["STAGE 2: PING -L -F"] += "| ($hostName)`t`t| ($SourceIP)`t| ($TargetMachine)`t`t| ($TargetIP)`t| $PacketSize Bytes`t| $Success`t|"

                                    $Success | Should Be $True
                                } 

                                Write-Host "`r`n####################################`r`n"
                                "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                            } 

                        }
                    
                    }   

                }

            }

        }
        
        Write-Host "RESULTS Stage 2: PING -L -F`r`n"
        "RESULTS Stage 2: PING -L -F`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        
        ($Results["STAGE 2: PING -L -F"]) | ForEach-Object {

            Write-Host $_ 
            $_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

        }
    }

    # ####################################
    # # Test Machines for TCP CTS Traffic Capability
    # ####################################
    if ($StageNumber -ge 3) {

        Context "Synthetic Connection Test (TCP)`r`n" {

            Write-Host "####################################`r`n"
            Write-Host "VERBOSE: Testing Connectivity Stage 3: TCP CTS Traffic`r`n"
            Write-Host "####################################`r`n"
            "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "VERBOSE: Testing Connectivity Stage 3: TCP CTS Traffic`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 

            $Results["STAGE 3: TCP CTS Traffic"] = @("| SERVER MACHINE`t| SERVER NIC`t`t| SERVER BPS`t`t| CLIENT MACHINE`t| CLIENT NIC`t`t| CLIENT BPS`t`t| THRESHOLD (>80%) |")
            $Failures["STAGE 3: TCP CTS Traffic"] = @("| SERVER MACHINE`t| SERVER NIC`t`t| SERVER BPS`t`t| CLIENT MACHINE`t| CLIENT NIC`t`t| CLIENT BPS`t`t| THRESHOLD (>80%) |")

            $TestNetwork | ForEach-Object {

                "VERBOSE: Testing CTS Traffic (TCP) Connectivity on Machine: $($_.Name)" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                $ServerNetworkNode = $_
                $ServerName = $_.Name

                $ServerNetworkNode.InterfaceListStruct.Values | ForEach-Object {
                    
                    $ServerStatus = $_.Status

                    if ($ServerStatus) {
                        Write-Host "VERBOSE: Testing CTS Traffic (TCP) Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n"
                        "VERBOSE: Testing CTS Traffic (TCP) Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                        $ServerIP = $_.IpAddress
                        $ServerSubnet = $_.Subnet
                        $ServerVLAN = $_.VLAN
                        $ServerLinkSpeed = $_.LinkSpeed

                        $TestNetwork | ForEach-Object {

                            $ClientNetworkNode = $_
                            $ClientName = $_.Name

                            $ClientNetworkNode.InterfaceListStruct.Values | ForEach-Object {

                                $ClientIP = $_.IpAddress
                                $ClientSubnet = $_.Subnet
                                $ClientVLAN = $_.VLAN
                                $ClientLinkSpeed = $_.LinkSpeed
                                $ClientStatus = $_.Status
                                
                                if (($ServerIP -NotLike $ClientIP) -And ($ServerSubnet -Like $ClientSubnet) -And ($ServerVLAN -Like $ClientVLAN) -And ($ClientStatus)) {

                                    It "Synthetic Connection Test (TCP) -- Verify Throughput is >80% reported: Client $($ClientIP) to Server $($ServerIP)`r`n" {
                                        
                                        $Success = $False
                                        Write-Host "Server $ServerName CMD: C:\Test-NetStack\tools\CTS-Traffic\ctsTraffic.exe -listen:$($ServerIP) -consoleverbosity:1 -ServerExitLimit:32 -TimeLimit:20000`r`n"
                                        "Server $ServerName CMD: C:\Test-NetStack\tools\CTS-Traffic\ctsTraffic.exe -listen:$($ServerIP) -consoleverbosity:1 -ServerExitLimit:32 -TimeLimit:20000`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        Write-Host "Client $ClientName CMD: C:\Test-NetStack\tools\CTS-Traffic\ctsTraffic.exe -target:$($ServerIP) -bind:$ClientIP -consoleverbosity:1 -iterations:2 -RateLimit:$ClientLinkSpeed`r`n"
                                        "Client $ClientName CMD: C:\Test-NetStack\tools\CTS-Traffic\ctsTraffic.exe -target:$($ServerIP) -bind:$ClientIP -consoleverbosity:1 -iterations:2 -RateLimit:$ClientLinkSpeed`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        
                                        $ServerOutput = Start-Job -ScriptBlock {
                                            $ServerIP = $Using:ServerIP
                                            $ServerLinkSpeed = $Using:ServerLinkSpeed
                                            Invoke-Command -Computername $Using:ServerName -ScriptBlock { cmd /c "C:\Test-NetStack\tools\CTS-Traffic\ctsTraffic.exe -listen:$Using:ServerIP -consoleverbosity:1 -ServerExitLimit:32 -TimeLimit:20000 2>&1" }
                                        }

                                        $ClientOutput = Invoke-Command -Computername $ClientName -ScriptBlock { cmd /c "C:\Test-NetStack\tools\CTS-Traffic\ctsTraffic.exe -target:$Using:ServerIP -bind:$Using:ClientIP -connections:32 -consoleverbosity:1 -iterations:2 2>&1" }
                                    
                                        Start-Sleep 1

                                        $ServerOutput = Receive-Job $ServerOutput

                                        $FlatServerOutput = @()
                                        $FlatClientOutput = @()
                                        $ServerOutput[20..($ServerOutput.Count-5)] | ForEach-Object {If ($_ -ne "") {$FlatServerOutput += ($_ -split '\D+' | Sort-Object -Unique)}}
                                        $ClientOutput[20..($ClientOutput.Count-5)] | ForEach-Object {If ($_ -ne "") {$FlatClientOutput += ($_ -split '\D+' | Sort-Object -Unique)}}
                                        $FlatServerOutput = ForEach($num in $FlatServerOutput) {if ($num -ne "") {[Long]::Parse($num)}} 
                                        $FlatClientOutput = ForEach($num in $FlatClientOutput) {if ($num -ne "") {[Long]::Parse($num)}}

                                        $ServerRecvBps = ($FlatServerOutput | Measure-Object -Maximum).Maximum * 8
                                        $ClientRecvBps = ($FlatClientOutput | Measure-Object -Maximum).Maximum * 8
                                        $Success = ($ServerRecvBps -gt ($ServerLinkSpeed, $ClientLinkSpeed | Measure-Object -Minimum).Minimum * .8) -and ($ClientRecvBps -gt ($ServerLinkSpeed, $ClientLinkSpeed | Measure-Object -Minimum).Minimum * .8)
                                        Write-Host "Server Bps $ServerRecvBps and Client Bps $ClientRecvBps`r`n"
                                        "Server Bps $ServerRecvBps and Client Bps $ClientRecvBps`r`n"| Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                                        Write-Host "TCP CTS Traffic Server Output: "
                                        Write-Host ($ServerOutput -match "SuccessfulConnections")
                                        $ServerOutput[($ServerOutput.Count-3)..$ServerOutput.Count] | ForEach-Object {Write-Host $_}
                                        Write-Host "`r`n"
                                        "TCP CTS Traffic Server Output: "| Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        ($ServerOutput -match "SuccessfulConnections") | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        $ServerOutput[($ServerOutput.Count-3)..$ServerOutput.Count] | ForEach-Object {$_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8}
                                        "`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                                        Write-Host "TCP CTS Traffic Client Output: "
                                        Write-Host ($ClientOutput -match "SuccessfulConnections")
                                        $ClientOutput[($ClientOutput.Count-3)..$ClientOutput.Count] | ForEach-Object {Write-Host $_}
                                        Write-Host "`r`n"
                                        "TCP CTS Traffic Client Output: "| Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        ($ClientOutput -match "SuccessfulConnections") | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        $ClientOutput[($ClientOutput.Count-3)..$ClientOutput.Count] | ForEach-Object {$_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8}
                                        "`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                                        $Results["STAGE 3: TCP CTS Traffic"] += "|($ServerName)`t| ($ServerIP)`t| $ServerRecvBps bps `t| ($ClientName)`t| ($ClientIP)`t| $ClientRecvBps bps`t| $SUCCESS |"
                                        if (-not $Success) {
                                            $Failures["STAGE 3: TCP CTS Traffic"] += "|($ServerName)`t| ($ServerIP)`t| $ServerRecvBps bps `t| ($ClientName)`t| ($ClientIP)`t| $ClientRecvBps bps`t| $SUCCESS |"
                                        }

                                        $Success | Should Be $True
                                    }
                                    Write-Host "`r`n####################################`r`n"
                                    "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                } 
                            }
                        }
                    } 
                }
            }
        }

        Write-Host "RESULTS Stage 3: TCP CTS Traffic`r`n"
        "RESULTS Stage 3: TCP CTS Traffic`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        
        ($Results["STAGE 3: TCP CTS Traffic"]) | ForEach-Object {

            Write-Host $_ 
            $_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

        }
    }

    # ####################################
    # # Test Machines for NDK Ping Capability
    # ####################################
    if ($StageNumber -ge 4) {

        Context "Basic RDMA Connectivity Test (NDK Ping)`r`n" {

            Write-Host "####################################`r`n"
            Write-Host "VERBOSE: Testing Connectivity Stage 4: NDK Ping`r`n"
            Write-Host "####################################`r`n"
            "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "VERBOSE: Testing Connectivity Stage 4: NDK Ping`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            
            $Results["STAGE 4: NDK Ping"] = @("| SERVER MACHINE`t| SERVER NIC`t`t| CLIENT MACHINE`t| CLIENT NIC`t`t| CONNECTIVITY`t|")
            $Failures["STAGE 4: NDK Ping"] = @("| SERVER MACHINE`t| SERVER NIC`t`t| CLIENT MACHINE`t| CLIENT NIC`t`t| CONNECTIVITY`t|")

            $TestNetwork | ForEach-Object {
        
                Write-host "VERBOSE: Testing NDK Ping Connectivity on Machine: $($_.Name)"
                "VERBOSE: Testing NDK Ping Connectivity on Machine: $($_.Name)" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                $ServerNetworkNode = $_
                $ServerName = $_.Name
        
                $ServerRdmaInterfaceList = $ServerNetworkNode.InterfaceListStruct.Values | where Name -In $ServerNetworkNode.RdmaNetworkAdapters.Name | where RdmaEnabled
        
                $ServerRdmaInterfaceList | ForEach-Object {
                    
                    $ServerStatus = $_.Status

                    if ($ServerStatus) {
                        
                        Write-Host "VERBOSE: Testing NDK Ping Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n"
                        "VERBOSE: Testing NDK Ping Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                        
                        $ServerIP = $_.IpAddress
                        $ServerIF = $_.IfIndex
                        $ServerSubnet = $_.Subnet
                        $ServerVLAN = $_.VLAN
            
                        $TestNetwork | ForEach-Object {
            
                            $ClientNetworkNode = $_
                            $ClientName = $_.Name
            
                            $ClientRdmaInterfaceList = $ClientNetworkNode.InterfaceListStruct.Values | where Name -In $ClientNetworkNode.RdmaNetworkAdapters.Name | where RdmaEnabled
            
                            $ClientRdmaInterfaceList | ForEach-Object {
            
                                $ClientIP = $_.IpAddress
                                $ClientIF = $_.IfIndex
                                $ClientSubnet = $_.Subnet
                                $ClientVLAN = $_.VLAN
                                $ClientStatus = $_.Status
            
                                if (($ServerIP -NotLike $ClientIP) -And ($ServerSubnet -Like $ClientSubnet) -And ($ServerVLAN -Like $ClientVLAN) -And $ClientStatus) {
                                    
                                    Write-Host "`r`n##################################################`r`n"
                                    "`r`n##################################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                    
                                    It "Basic RDMA Connectivity Test -- Verify Basic Rdma Connectivity: Client $ClientIP to Server $ServerIP" {
                                        
                                        $ServerSuccess = $False
                                        $ClientSuccess = $False
                                        Write-Host "Server $ServerName CMD: NdkPing -S -ServerAddr $($ServerIP):9000  -ServerIf $ServerIF -TestType rping -W 5`r`n"
                                        "Server $ServerName CMD: NdkPing -S -ServerAddr $($ServerIP):9000  -ServerIf $ServerIF -TestType rping -W 5`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        Write-Host "Client $ClientName CMD: NdkPing -C -ServerAddr  $($ServerIP):9000 -ClientAddr $ClientIP -ClientIf $ClientIF -TestType rping`r`n"
                                        "Client $ClientName CMD: NdkPing -C -ServerAddr  $($ServerIP):9000 -ClientAddr $ClientIP -ClientIf $ClientIF -TestType rping`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                
                                        $ServerOutput = Start-Job -ScriptBlock {
                                            $ServerIP = $Using:ServerIP
                                            $ServerIF = $Using:ServerIF
                                            Invoke-Command -Computername $Using:ServerName -ScriptBlock { cmd /c "NdkPing -S -ServerAddr $($Using:ServerIP):9000  -ServerIf $Using:ServerIF -TestType rping -W 5 2>&1" }
                                        }
                                        Start-Sleep -Seconds 1
                                        $ClientOutput = Invoke-Command -Computername $ClientName -ScriptBlock { cmd /c "NdkPing -C -ServerAddr  $($Using:ServerIP):9000 -ClientAddr $Using:ClientIP -ClientIf $Using:ClientIF -TestType rping 2>&1" }
                                        Start-Sleep -Seconds 5
                
                                        $ServerOutput = Receive-Job $ServerOutput
                                    
                                        Write-Host "NDK Ping Server Output: "
                                        $ServerOutput | ForEach-Object {$ServerSuccess = $_ -match 'completes';Write-Host $_}
                                        Write-Host "`r`n"

                                        "NDK Ping Server Output: "| Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        $ServerOutput | ForEach-Object {$_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8}
                                        "`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                
                                        Write-Host "NDK Ping Client Output: "
                                        $ClientOutput[0..($ClientOutput.Count-4)] | ForEach-Object {$ClientSuccess = $_ -match 'completes';Write-Host $_}
                                        "NDK Ping Client Output: "| Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        $ClientOutput | ForEach-Object {$_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8}
                                        Write-Host "`r`n##################################################`r`n"
                                        "`r`n##################################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                                        $Success = $ServerSuccess -and $ClientSuccess

                                        $Results["STAGE 4: NDK Ping"] += "| ($ServerName)`t`t| ($ServerIP)`t| ($ClientName)`t`t| ($ClientIP)`t| $Success`t`t|"
                                        if (-not $Success) {
                                            $Failures["STAGE 4: NDK Ping"] += "| ($ServerName)`t`t| ($ServerIP)`t| ($ClientName)`t`t| ($ClientIP)`t| $Success`t`t|"
                                        }

                                        $Success | Should Be $True
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Write-Host "RESULTS Stage 4: NDK Ping`r`n"
        "RESULTS Stage 4: NDK Ping`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        
        ($Results["STAGE 4: NDK Ping"]) | ForEach-Object {

            Write-Host $_ 
            $_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

        }
    }

    # ###################################
    # # Test Machines for NDK Perf Capability
    # ###################################
    if ($StageNumber -ge 5) {

        Context "1:1 RDMA Congestion Test (NDK Perf)`r`n" {
    
            Write-Host "####################################`r`n"
            Write-Host "VERBOSE: Testing Connectivity Stage 5: NDK Perf`r`n"
            Write-Host "####################################`r`n"
            "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "VERBOSE: Testing Connectivity Stage 5: NDK Perf`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 

            $Results["STAGE 5: NDK Perf"] = @("| SERVER MACHINE`t| SERVER NIC`t`t| SERVER BPS`t`t| CLIENT MACHINE| CLIENT NIC`t`t| CLIENT BPS`t`t| THRESHOLD (>80%) |")
            $Failures["STAGE 5: NDK Perf"] = @("| SERVER MACHINE`t| SERVER NIC`t`t| SERVER BPS`t`t| CLIENT MACHINE| CLIENT NIC`t`t| CLIENT BPS`t`t| THRESHOLD (>80%) |")

            $TestNetwork | ForEach-Object {

                Write-Host "VERBOSE: Testing NDK Perf Connectivity on Machine: $($_.Name)"
                "VERBOSE: Testing NDK Perf Connectivity on Machine: $($_.Name)" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                $ServerNetworkNode = $_
                $ServerName = $_.Name

                $ServerRdmaInterfaceList = $ServerNetworkNode.InterfaceListStruct.Values | where Name -In $ServerNetworkNode.RdmaNetworkAdapters.Name | where RdmaEnabled

                $ServerRdmaInterfaceList | ForEach-Object {

                    $ServerStatus = $_.Status

                    if($ServerStatus) {
                        
                        Write-Host "VERBOSE: Testing NDK Perf Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n"
                        "VERBOSE: Testing NDK Perf Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        
                        $ServerIP = $_.IpAddress
                        $ServerIF = $_.IfIndex
                        $ServerSubnet = $_.Subnet
                        $ServerVLAN = $_.VLAN
                        $ServerLinkSpeed = $_.LinkSpeed
                        $ServerInterfaceDescription = $_.Description

                        $TestNetwork | ForEach-Object {
        
                            $ClientNetworkNode = $_
                            $ClientName = $_.Name
                            
                            $ClientRdmaInterfaceList = $ClientNetworkNode.InterfaceListStruct.Values | where Name -In $ClientNetworkNode.RdmaNetworkAdapters.Name | where RdmaEnabled
        
                            $ClientRdmaInterfaceList | ForEach-Object {
        
                                $ClientIP = $_.IpAddress
                                $ClientIF = $_.IfIndex
                                $ClientSubnet = $_.Subnet
                                $ClientVLAN = $_.VLAN
                                $ClientStatus = $_.Status
                                $ClientLinkSpeed = $_.LinkSpeed
                                $ClientInterfaceDescription = $_.Description
        
                                if (($ServerIP -NotLike $ClientIP) -And ($ServerSubnet -Like $ClientSubnet) -And ($ServerVLAN -Like $ClientVLAN) -And $ClientStatus) {
        
                                    Write-Host "`r`n##################################################`r`n"
                                    "`r`n##################################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        
                                    It "1:1 RDMA Congestion Test -- Stress RDMA Transaction Between Two Singular NICs: Client $ClientIP to Server $ServerIP" {
                                        
                                        $ServerSuccess = $False
                                        $ClientSuccess = $False
                                        Start-Sleep -Seconds 1
        
                                        Write-Host "Server $ServerName CMD: C:\Test-NetStack\tools\NDK-Perf\NDKPerfCmd.exe -S -ServerAddr $($ServerIP):9000  -ServerIf $ServerIF -TestType rping -W 5`r`n"
                                        "Server $ServerName CMD: C:\Test-NetStack\tools\NDK-Perf\NDKPerfCmd.exe -S -ServerAddr $($ServerIP):9000  -ServerIf $ServerIF -TestType rping -W 5`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        Write-Host "Client $ClientName CMD: C:\Test-NetStack\tools\NDK-Perf\NDKPerfCmd.exe -C -ServerAddr  $($ServerIP):9000 -ClientAddr $ClientIP -ClientIf $ClientIF -TestType rping`r`n"
                                        "Client $ClientName CMD: C:\Test-NetStack\tools\NDK-Perf\NDKPerfCmd.exe -C -ServerAddr  $($ServerIP):9000 -ClientAddr $ClientIP -ClientIf $ClientIF -TestType rping`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        
                                        $ServerCounter = Start-Job -ScriptBlock {
                                            $ServerName = $Using:ServerName
                                            $ServerInterfaceDescription = $Using:ServerInterfaceDescription
                                            Get-Counter -ComputerName $ServerName -Counter "\RDMA Activity($ServerInterfaceDescription)\RDMA Inbound Bytes/sec" -MaxSamples 5 #-ErrorAction Ignore
                                        }

                                        $ServerOutput = Start-Job -ScriptBlock {
                                            $ServerIP = $Using:ServerIP
                                            $ServerIF = $Using:ServerIF
                                            Invoke-Command -Computername $Using:ServerName -ScriptBlock { cmd /c "C:\Test-NetStack\tools\NDK-Perf\NDKPerfCmd.exe -S -ServerAddr $($Using:ServerIP):9000  -ServerIf $Using:ServerIF -TestType rping -W 5 2>&1" }
                                        }

                                        Start-Sleep -Seconds 1
                                        
                                        $ClientCounter = Start-Job -ScriptBlock {
                                            $ClientName = $Using:ClientName
                                            $ClientInterfaceDescription = $Using:ClientInterfaceDescription
                                            Get-Counter -ComputerName $ClientName -Counter "\RDMA Activity($ClientInterfaceDescription)\RDMA Outbound Bytes/sec" -MaxSamples 5
                                        }
                                        
                                        $ClientOutput = Invoke-Command -Computername $ClientName -ScriptBlock { cmd /c "C:\Test-NetStack\tools\NDK-Perf\NDKPerfCmd.exe -C -ServerAddr  $($Using:ServerIP):9000 -ClientAddr $Using:ClientIP -ClientIf $Using:ClientIF -TestType rping 2>&1" }
                                        
                                        $read = Receive-Job $ServerCounter
                                        $written = Receive-Job $ClientCounter

                                        $FlatServerOutput = $read.Readings.split(":") | ForEach-Object {
                                            try {[uint64]($_) * 8} catch{}
                                        }
                                        $FlatClientOutput = $written.Readings.split(":") | ForEach-Object {
                                            try {[uint64]($_) * 8} catch{}
                                        }
                                        $ServerBytesPerSecond = ($FlatServerOutput | Measure-Object -Maximum).Maximum
                                        $ClientBytesPerSecond = ($FlatClientOutput | Measure-Object -Maximum).Maximum

                                        Write-Host $ServerBytesPerSecond
                                        Write-Host $ClientBytesPerSecond

                                        Start-Sleep -Seconds 5
                                        
                                        $ServerOutput = Receive-Job $ServerOutput
                                        
                                        Write-Host "NDK Perf Server Output: "
                                        $ServerOutput | ForEach-Object {$ServerSuccess = $_ -match 'completes';Write-Host $_}
                                        Write-Host "`r`n"
                                        "NDK Perf Server Output: "| Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        $ServerOutput | ForEach-Object {$_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8}
                                        "`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        
                                        Write-Host "NDK Perf Client Output: "
                                        $ClientOutput[0..($ClientOutput.Count-4)] | ForEach-Object {$ClientSuccess = $_ -match 'completes';Write-Host $_}
                                        "NDK Perf Client Output: "| Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        $ClientOutput | ForEach-Object {$_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8}
                                        Write-Host "`r`n##################################################`r`n"
                                        "`r`n##################################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                        
                                        $Success = ($ServerBytesPerSecond -gt ($ServerLinkSpeed, $ClientLinkSpeed | Measure-Object -Minimum).Minimum * .8) -and ($ClientBytesPerSecond -gt ($ServerLinkSpeed, $ClientLinkSpeed | Measure-Object -Minimum).Minimum * .8)

                                        $Results["STAGE 5: NDK Perf"] += "|($ServerName)`t| ($ServerIP)`t| $ServerBytesPerSecond bps `t| ($ClientName)`t| ($ClientIP)`t| $ClientBytesPerSecond bps`t| $SUCCESS |"
                                        if (-not $Success) {
                                            $Failures["STAGE 5: NDK Perf"] += "|($ServerName)`t| ($ServerIP)`t| $ServerBytesPerSecond bps `t| ($ClientName)`t| ($ClientIP)`t| $ClientBytesPerSecond bps`t| $SUCCESS |"
                                        }

                                        $Success | Should Be $True
                                    }
                                } 
                            }
                        }
                    }
                }
            }
        }
        
        Write-Host "RESULTS Stage 5: NDK Perf`r`n"
        "RESULTS Stage 5: NDK Perf`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        
        ($Results["STAGE 5: NDK Perf"]) | ForEach-Object {

            Write-Host $_ 
            $_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

        }
    }

    # # ##################################
    # # Test Machines for NDK Perf (N to 1) Capability
    # # ##################################
    if ($StageNumber -ge 6) {

        Context "(N:1) RDMA Congestion Test (NDK Perf)`r`n" {

            Write-Host "####################################`r`n"
            Write-Host "VERBOSE: Testing Connectivity Stage 6: NDK Perf (N : 1)`r`n"
            Write-Host "####################################"
            "####################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "VERBOSE: Testing Connectivity Stage 6: NDK Perf (N : 1)`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 
            "####################################" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8 

            $Results["STAGE 6: NDK Perf (N : 1)"] = @("| SERVER MACHINE`t| SERVER NIC`t`t| SERVER BPS`t`t| CLIENT MACHINE`t| CLIENT NIC`t| CLIENT BPS`t`t| THRESHOLD (>80%) |")
            $ResultString = ""
            $Failures["STAGE 6: NDK Perf (N : 1)"] = @("| SERVER MACHINE`t| SERVER NIC`t`t| SERVER BPS`t`t| CLIENT MACHINE`t| CLIENT NIC`t| CLIENT BPS`t`t| THRESHOLD (>80%) |")

            $TestNetwork | ForEach-Object {

                "VERBOSE: Testing NDK Perf Connectivity on Machine: $($_.Name)" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                $ServerNetworkNode = $_
                $ServerName = $_.Name

                $ServerRdmaInterfaceList = $ServerNetworkNode.InterfaceListStruct.Values | where Name -In $ServerNetworkNode.RdmaNetworkAdapters.Name | where RdmaEnabled

                $ServerRdmaInterfaceList | ForEach-Object {
                
                    Write-Host "VERBOSE: Testing NDK Perf N:1 Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n"
                    "VERBOSE: Testing NDK Perf N:1 Connectivity for Subnet: $($_.Subnet) and VLAN: $($_.VLAN)`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                    $ServerIP = $_.IpAddress
                    $ServerIF = $_.IfIndex
                    $ServerSubnet = $_.Subnet
                    $ServerVLAN = $_.VLAN
                    $ServerLinkSpeed = $_.LinkSpeed
                    $ServerInterfaceDescription = $_.Description

                    $ResultString = ""
                    $ClientNetwork = $TestNetwork | where Name -ne $ServerName

                    for ($i = 1; $i -lt $MachineCluster.Count - 1; $i++) {
                        
                        It "(N:1) RDMA Congestion Test (Client $ClientIP to Server $ServerIP)" {

                            $RandomClientNodes = If ($ClientNetwork.Count -eq 1) { $ClientNetwork[0] } Else { $ClientNetwork[0..$i] }
                            $j = 0

                            $ServerOutput = @()
                            $ClientOutput = @()
                            $ServerCounter = @()
                            $ClientCounter = @()

                            $ServerSuccess = $True
                            $ClientSuccess = $True

                            $RandomClientNodes | ForEach-Object {

                                Start-Sleep -Seconds 1
                            
                                $ClientName = $_.Name
                                $ClientInterface = $_.InterfaceListStruct.Values | where Name -In $_.RdmaNetworkAdapters.Name | where Subnet -Like $ServerSubnet | where VLAN -Like $ServerVLAN
                                $ClientIP = $ClientInterface.IpAddress
                                $ClientIF = $ClientInterface.IfIndex
                                $ClientInterfaceDescription = $ClientInterface.Description

                                Write-Host "Server $ServerName CMD: C:\Test-NetStack\tools\NDK-Perf\NDKPerfCmd.exe -S -ServerAddr $($ServerIP):900$j  -ServerIf $ServerIF -TestType rping -W 5`r`n"
                                "Server $ServerName CMD: C:\Test-NetStack\tools\NDK-Perf\NDKPerfCmd.exe -S -ServerAddr $($ServerIP):900$j  -ServerIf $ServerIF -TestType rping -W 5`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                                Write-Host "Client $($_.Name) CMD: C:\Test-NetStack\tools\NDK-Perf\NDKPerfCmd.exe -C -ServerAddr  $($ServerIP):900$j -ClientAddr $ClientIP -ClientIf $ClientIF -TestType rping`r`n"
                                "Client $($_.Name) CMD: C:\Test-NetStack\tools\NDK-Perf\NDKPerfCmd.exe -C -ServerAddr  $($ServerIP):900$j -ClientAddr $ClientIP -ClientIf $ClientIF -TestType rping`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                                $ServerCounter += Start-Job -ScriptBlock {
                                    $ServerName = $Using:ServerName
                                    $ServerInterfaceDescription = $Using:ServerInterfaceDescription
                                    Get-Counter -ComputerName $ServerName -Counter "\RDMA Activity($ServerInterfaceDescription)\RDMA Inbound Bytes/sec" -MaxSamples 5 #-ErrorAction Ignore
                                }

                                $ServerOutput += Start-Job -ScriptBlock {
                                    $ServerIP = $Using:ServerIP
                                    $ServerIF = $Using:ServerIF
                                    $j = $Using:j
                                    Invoke-Command -Computername $Using:ServerName -ScriptBlock { cmd /c "C:\Test-NetStack\tools\NDK-Perf\NdkPerfCmd.exe -S -ServerAddr $($Using:ServerIP):900$Using:j  -ServerIf $Using:ServerIF -TestType rping -W 5 2>&1" }
                                }

                                $ClientCounter += Start-Job -ScriptBlock {
                                    $ClientName = $Using:ClientName
                                    $ClientInterfaceDescription = $Using:ClientInterfaceDescription
                                    Get-Counter -ComputerName $ClientName -Counter "\RDMA Activity($ClientInterfaceDescription)\RDMA Outbound Bytes/sec" -MaxSamples 5
                                }

                                $ClientOutput += Start-Job -ScriptBlock {
                                    $ServerIP = $Using:ServerIP
                                    $ClientIP = $Using:ClientIP
                                    $ClientIF = $Using:ClientIF
                                    $j = $Using:j
                                    Invoke-Command -Computername $Using:ClientName -ScriptBlock { cmd /c "C:\Test-NetStack\tools\NDK-Perf\NdkPerfCmd.exe -C -ServerAddr  $($Using:ServerIP):900$Using:j -ClientAddr $($Using:ClientIP) -ClientIf $($Using:ClientIF) -TestType rping 2>&1" }
                                }
                                Start-Sleep -Seconds 1
                                $j++
                            }
                            
                            Start-Sleep -Seconds 10
                            Write-Host "##################################################`r`n"
                            "##################################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                            $ServerBytesPerSecond = 0
                            $k = 0
                            $ServerCounter | ForEach-Object {
                                
                                $read = Receive-Job $_

                                $FlatServerOutput = $read.Readings.split(":") | ForEach-Object {
                                    try {[uint64]($_) * 8} catch{}
                                }
                                $ClientInterface = $RandomClientNodes[$k].InterfaceListStruct.Values | where Name -In $RandomClientNodes[$k].RdmaNetworkAdapters.Name | where Subnet -Like $ServerSubnet | where VLAN -Like $ServerVLAN
                                $ClientLinkSpeed = $ClientInterface.LinkSpeed
                                $ServerBytesPerSecond = ($FlatServerOutput | Measure-Object -Maximum).Maximum
                                $ServerSuccess = $ServerSuccess -and ($ServerBytesPerSecond -gt ($ServerLinkSpeed, $ClientLinkSpeed | Measure-Object -Minimum).Minimum * .8)
                                
                                $k++
                            }
                            $ResultString += "| ($ServerName)`t`t| ($ServerIP)`t| $ServerBytesPerSecond `t`t|" 

                            $ServerOutput | ForEach-Object {
                                $job = Receive-Job $_
                                Write-Host $job
                                $job | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                            }
                            Write-Host "`r`n##################################################`r`n"
                            "`r`n##################################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                            $k = 0
                            $ClientCounter | ForEach-Object {
                                
                                $written = Receive-Job $_
                                $FlatClientOutput = $written.Readings.split(":") | ForEach-Object {
                                    try {[uint64]($_) * 8} catch{}
                                }
                                $ClientName = $RandomClientNodes[$k].Name
                                $ClientInterface = $RandomClientNodes[$k].InterfaceListStruct.Values | where Name -In $RandomClientNodes[$k].RdmaNetworkAdapters.Name | where Subnet -Like $ServerSubnet | where VLAN -Like $ServerVLAN
                                $ClientIP = $ClientInterface.IpAddress
                                $ClientLinkSpeed = $ClientInterface.LinkSpeed
                                $ClientBytesPerSecond = ($FlatClientOutput | Measure-Object -Maximum).Maximum
                                $ClientSuccess = $ClientSuccess -and ($ClientBytesPerSecond -gt ($ServerLinkSpeed, $ClientLinkSpeed | Measure-Object -Minimum).Minimum * .8) 
                                
                                $ResultString +=  "`r|`t`t`t`t`t`t`t`t`t| $($ClientName)`t`t| $($ClientIP)`t|"
                                $ResultString += " $($job[3] -match "completes")`t`t`t| $ClientBytesPerSecond bps`t|"
                                $k++
                            }

                            $k = 0
                            $ClientOutput | ForEach-Object {
                                $job = Receive-Job $_
                                Write-Host $job
                                $job | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
                            }
                            Write-Host "`r`n##################################################`r`n"
                            "`r`n##################################################`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

                            $Success = $ServerSuccess -and $ClientSuccess
                            
                            $Results["STAGE 6: NDK Perf (N : 1)"] += $ResultString
                            if (-not $Success) {
                                $Failures["STAGE 6: NDK Perf (N : 1)"] += $ResultString
                            }

                            $Success | Should Be $True    
                        }

                    }

                }

            }

        }

        Write-Host "RESULTS Stage 6: NDK Perf (N : 1)`r`n"
        "RESULTS Stage 6: NDK Perf (N : 1)`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        
        $ResultString += "| ($ServerName)`t`t| ($ServerIP)`t|"
        ($Results["STAGE 6: NDK Perf (N : 1)"]) | ForEach-Object {

            Write-Host $_ 
            $_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

        }
    }

    Write-Host "`r`nFAILURES STAGES 1-6`r`n"
    "`r`nFAILURES STAGES 1-6`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

    ($Failures.Keys | Sort-Object) | ForEach-Object {

        Write-Host $_ 
        $_ | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8
        Write-Host $Failures[$_] 
        $Failures[$_]  | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

    }

    $TestNetworkJson = ConvertTo-Json $TestNetwork -Depth 99

    $TestNetworkJson | Set-Content "C:\Test-NetStack\Test-NetStack-Network-Info.txt"

    $endTime = Get-Date -format:'MM-dd-yyyy HH:mm:ss'

    Write-Host "Ending Test-NetStack: $endTime`r`n"
    "Ending Test-NetStack: $endTime`r`n" | Out-File 'C:\Test-NetStack\Test-NetStack-Output.txt' -Append -Encoding utf8

}