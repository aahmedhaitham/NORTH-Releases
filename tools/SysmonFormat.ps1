function Read-SysmonFields($event) {
    $xml = [xml]$event.ToXml()
    $fields = @{}
    foreach ($node in $xml.GetElementsByTagName('Data')) {
        $fields[$node.GetAttribute('Name')] = $node.InnerText
    }
    return $fields
}

function Export-NorthEvent($record) {
    $fields = $record.fields
    return @{
        agent = @{ id = 'sysmon-local-01'; name = 'WIN-PC' }
        data = @{ win = @{
            system = @{
                channel = 'Microsoft-Windows-Sysmon/Operational'
                eventID = [string]$record.event.Id
                eventRecordID = [string]$record.event.RecordId
                systemTime = $record.event.TimeCreated.ToUniversalTime().ToString('o')
            }
            eventdata = @{
                image = [IO.Path]::GetFileName([string]$fields.Image)
                processGuid = [string]$fields.ProcessGuid
                parentProcessGuid = [string]$fields.ParentProcessGuid
                destinationIp = [string]$fields.DestinationIp
                targetFilename = [IO.Path]::GetFileName([string]$fields.TargetFilename)
            }
        } }
    }
}
