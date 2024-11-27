# Define the program name
$programName = "netprobclient"

# Start the program
Start-Process -FilePath ".\netprobclient.exe" -ArgumentList "-send -stat 1000 -rhost localhost -rport 4180 -proto udp -pktsize 10000 -pktrate 0 -pktnum 200000 -sbufsize 20000 -rbufsize 20000"

# Initialize variables
$cpuUsage = 0
$interval = 0.1 # Interval in seconds

# Loop to monitor the process
while ($true) {
    # Get the process
    $process = Get-Process -Name $programName -ErrorAction SilentlyContinue

    if ($process) {
        # Calculate CPU usage using TotalProcessorTime
        $cpuTime = $process.TotalProcessorTime.TotalSeconds
        $elapsedTime = (Get-Date) - $process.StartTime
        $cpuUsage = ($cpuTime / $elapsedTime.TotalSeconds) * 100

        # Output the CPU usage
        Write-Output "CPU Usage: {0:N2}%" -f $cpuUsage
    }
    else {
        # Exit loop if the process no longer exists
        break
    }

    # Wait for a short interval before checking again
    Start-Sleep -Seconds $interval
}

# Output the final CPU usage
Write-Output "Final CPU Usage: {0:N2}%" -f $cpuUsage
