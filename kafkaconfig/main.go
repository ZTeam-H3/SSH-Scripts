package main

import (
	"SSH-Spider/moudle"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"log"
	"strings"
)

func main() {

	var curip, curusername, pwd string

	flag.StringVar(&curip, "ip", "10.1.71.4", "input ip your want to start")
	flag.StringVar(&curusername, "username", "cfae", "input username")
	flag.StringVar(&pwd, "password", "Cfae@123_2021", "input the path of privatekey")
	flag.Parse()




	info := moudle.IpInfo{
		Ip:   curip,
		Port: 22,
	}
	//
	config := moudle.Sshconfig(curusername, pwd)



	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", info.Ip, info.Port), config)

		if  err != nil{
			panic(err)
		}

	sconn := moudle.Connection{
		client,
		pwd,
	}

	var cmds []string
	cmd := "sudo find /app -name \"*.properties\""

	cmds = append(cmds,cmd)
	op,serr := sconn.SendCommands(cmds,5)

	if serr != nil {
		log.Fatal(err)
	}
	cmdlist := handlerfile(op)
	filecontent,serr := sconn.SendCommands(cmdlist,5)

	if serr != nil {
		log.Fatal(err)
	}

	fmt.Println(string(filecontent))


}


func handlerfile(op []byte)[]string{
	back := string(op)
	backlist := strings.Split(back,"\n")

	var cmdlist []string
	for _,info := range backlist{
		if strings.Contains(info,"/app/kafka"){

			cmdlist = append(cmdlist, "sudo cat " + strings.Trim(info,"\r"))
		}
	}
	return cmdlist
}

