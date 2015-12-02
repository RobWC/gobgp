// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"net"
	"strconv"
	"sync"

	log "github.com/Sirupsen/logrus"
	"github.com/robwc/gobgp/packet"

	"os"
	"os/signal"
	"syscall"
)

// BFDD BDF Daemon struct
type BFDD struct {
}

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGTERM)

	var listenerwg sync.WaitGroup

	log.Info("gobfdd started")

	bfdctrl := net.JoinHostPort("", strconv.Itoa(bgp.BFD_CTRL_PORT))
	bfdctrladdr, _ := net.ResolveUDPAddr("udp", bfdctrl)

	bfdctrll, err := net.ListenUDP("udp", bfdctrladdr)
	if err != nil {
		log.Info(err)
		os.Exit(1)
	}

	bfdecho := net.JoinHostPort("", strconv.Itoa(bgp.BFD_ECHO_PORT))
	bfdechoaddr, _ := net.ResolveUDPAddr("udp", bfdecho)

	bfdechol, err := net.ListenUDP("udp", bfdechoaddr)
	if err != nil {
		log.Info(err)
		os.Exit(1)
	}

	listenerwg.Add(1)
	go func() {
		for {
			var msgbuff []byte
			var oobbuff []byte
			mlen, ooblen, flags, addr, err := bfdctrll.ReadMsgUDP(msgbuff, oobbuff)
			if err != nil {
				log.Error(err)
				continue
			}

			log.Debugf("Control packet recieved from %s with flags %d", addr.String(), flags)

			if mlen > 0 {
				_, _ := bgp.ParseBFDCtrlMessage(msgbuff)
			}

			if ooblen > 0 {

			}

		}
	}()

	listenerwg.Add(1)
	go func() {
		for {
			var msgbuff []byte
			var oobbuff []byte
			mlen, ooblen, flags, addr, err := bfdechol.ReadMsgUDP(msgbuff, oobbuff)
			if err != nil {
				log.Error(err)
				continue
			}

			log.Debugf("Echo packet recieved from %s with flags %d", addr.String(), flags)

			if mlen > 0 {
				_, _ := bgp.ParseBFDEchoMessage(msgbuff)

			}

			if ooblen > 0 {

			}

		}
	}()

	listenerwg.Wait()

	for {
		select {
		case sig := <-sigCh:
			switch sig {
			case syscall.SIGHUP:
				log.Info("reset")

			case syscall.SIGKILL, syscall.SIGTERM:
				if err := bfdechol.Close(); err != nil {
					log.Error(err)
				}

				if err := bfdctrll.Close(); err != nil {
					log.Error(err)
				}

				log.Info("Waiting for connections to close")
				listenerwg.Wait()
			}
		}
	}
}
