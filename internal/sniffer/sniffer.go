package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../bpf/ssl_hook.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

import (
	"log"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	//only for kernels <5.11
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("removing memlock %s",err)
	}

	//load objects 
	var objs bpfObjects
	if err := loadBpfObjects(&objs,nil) ; err != nil{
		log.Fatalf("loading ebpf objects %s",err)
	}
	defer objs.Close()
	 
	
	//get ssl executable 
	exec, err := link.OpenExecutable("usr/lib/libssl.so.3")
	if err!= nil{
		log.Fatalf("opening executable %s",err)
	}

	//get hooks onto the specified symbols
	readentry, err := exec.Uprobe("SSL_read",objs.SslReadEntry,nil):
	if err!= nil{
		log.Fatalf("loading sslreadentry %s",err)
	}
	defer readentry.Close()
	
	readexit, err := exec.Uretprobe("SSL_read",objs.SslReadExit,nil)
	if err!= nil{
		log.Fatalf("loading sslreadexit %s",err)
	}
	defer readexit.Close()

	writeentry, err := exec.Uprobe("SSL_write",objs.SslWriteEntry,nil):
	if err!= nil{
		log.Fatalf("loading sslwriteentry %s",err)
	}
	defer writeentry.Close()
	
	writeexit, err := exec.Uretprobe("SSL_write",objs.SslWriteExit,nil):
		log.Fatalf("loading sslwriteexit %s",err)
	}
	defer writeexit.Close()




}
