package main
  
import (
    "bytes"
    "fmt"
    "log"
    "os/exec"
)

const ShellToUse = "bash"

func Shellout(command string) (error, string, string) {
    var stdout bytes.Buffer
    var stderr bytes.Buffer
    cmd := exec.Command(ShellToUse, "-c", command)
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr   
    err := cmd.Run()
    return err, stdout.String(), stderr.String()
}            
      
func main() {
    err, out, errout := Shellout("cd ~/gnbsim/example/ && sudo ./example -ip 10.250.176.14 3>&1 1>log.txt 2>&1")
    if err != nil {
        log.Printf("error: %v\n", err)
    }
    fmt.Println("--- stdout ---")
    fmt.Println(out)
    fmt.Println("--- stderr ---")
    fmt.Println(errout)
}
