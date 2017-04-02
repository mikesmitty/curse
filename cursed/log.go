package main

import (
	"fmt"
	"log"
)

type logTmpl struct {
	conf    *config
	ip      string
	reqType string
	rip     string
}

func (t *logTmpl) req(user string, code int, msg string) {
	// ip - ip of bastion server making request
	// reqType should be ssh or tls, depending on the handler logging this request
	// code - http status code in response
	// msg - message to be logged
	// rip - user's remote IP from bastion connection

	line := fmt.Sprintf("%s %s %s %d %s %s", t.ip, t.reqType, user, code, msg, t.rip)

	if t.conf.LogTimestamp {
		log.Print(line)
	} else {
		fmt.Println(line)
	}
}

func newLog(conf *config, ip, reqType, rip string) *logTmpl {
	t := logTmpl{
		conf:    conf,
		ip:      ip,
		reqType: reqType,
		rip:     rip,
	}

	return &t
}
