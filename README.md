Its part of [heplify-server](https://github.com/sipcapture/heplify-server). Possible to use inside your project.

###Example usage:
```go
    import (
        "github.com/custompbx/hepparser"
        "net"
    )  

    const maxPktLen = 8192
    const addr = "127.0.0.1:9060"

    func Listener() {
        ua, err := net.ResolveUDPAddr("udp", addr)
        if err != nil {
            return
        }
    
        uc, err := net.ListenUDP("udp", ua)
        if err != nil {
            return
        }
    
        for {
            buf := make([]byte, maxPktLen)
            n, err := uc.Read(buf)
            if err != nil {
                log.Printf("%v\n return", err)
                return
            } else if n > maxPktLen {
                continue
            }
            go parser(buf[:n])
        }
    }
    
    func parser(packet) {
        hepPacket, err := hepparser.DecodeHEP(packet)
        if err != nil {
            log.Println(err)
            return
        }
        // Do whatever with packet -- hepPacket
    }
```	
