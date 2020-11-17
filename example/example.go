package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hhorai/gnbsim/encoding/nas"
	"github.com/hhorai/gnbsim/encoding/ngap"
	"github.com/ishidawataru/sctp"
	"github.com/vishvananda/netlink"
	"github.com/wmnsk/go-gtp/gtpv1"
)

type testSession struct {
	conn  *sctp.SCTPConn
	info  *sctp.SndRcvInfo
	gnb   *ngap.GNB
	ue    *nas.UE
	uConn *gtpv1.UPlaneConn
}

func newTest() (t *testSession) {

	t = new(testSession)

	return
}

func setupSCTP() (conn *sctp.SCTPConn, info *sctp.SndRcvInfo) {

	var ip = flag.String("ip", "localhost", "destinaion ip address")
	var port = flag.Int("port", 38412, "destination port")
	var lport = flag.Int("lport", 38412, "local port")

	flag.Parse()

	ips := []net.IPAddr{}

	for _, i := range strings.Split(*ip, ",") {
		a, _ := net.ResolveIPAddr("ip", i)
		ips = append(ips, *a)
	}

	addr := &sctp.SCTPAddr{
		IPAddrs: ips,
		Port:    *port,
	}

	var laddr *sctp.SCTPAddr
	if *lport != 0 {
		laddr = &sctp.SCTPAddr{
			Port: *lport,
		}
	}

	conn, err := sctp.DialSCTP("sctp", laddr, addr)
	if err != nil {
		log.Fatalf("failed to dial: %v", err)
	}
	log.Printf("Dail LocalAddr: %s; RemoteAddr: %s",
		conn.LocalAddr(), conn.RemoteAddr())

	sndbuf, err := conn.GetWriteBuffer()
	rcvbuf, err := conn.GetReadBuffer()
	log.Printf("SndBufSize: %d, RcvBufSize: %d", sndbuf, rcvbuf)

	ppid := 0
	info = &sctp.SndRcvInfo{
		Stream: uint16(ppid),
		PPID:   0x3c000000,
	}

	conn.SubscribeEvents(sctp.SCTP_EVENT_DATA_IO)

	return
}

func (t *testSession) sendtoAMF(pdu []byte) {

	n, err := t.conn.SCTPWrite(pdu, t.info)
	if err != nil {
		log.Fatalf("failed to write: %v", err)
	}
	log.Printf("write: len %d, info: %+v", n, t.info)
	return
}

func (t *testSession) recvfromAMF(timeout time.Duration) {

	const defaultTimer = 10 // sec

	if timeout == 0 {
		timeout = defaultTimer
	}

	c := make(chan bool, 1)
	go func() {
		buf := make([]byte, 1500)
		n, info, err := t.conn.SCTPRead(buf)
		t.info = info

		if err != nil {
			log.Fatalf("failed to read: %v", err)
		}
		log.Printf("read: len %d, info: %+v", n, t.info)

		buf = buf[:n]
		fmt.Printf("dump: %x\n", buf)
		t.gnb.Decode(&buf)
		c <- true
	}()
	select {
	case <-c:
		break
	case <-time.After(timeout * time.Second):
		log.Printf("read: timeout")
	}
	return
}

func initRAN(ctx context.Context) (t *testSession) {

	t = new(testSession)
	gnb := ngap.NewNGAP("example.json")
	gnb.SetDebugLevel(1)

	conn, info := setupSCTP()

	t.gnb = gnb
	t.conn = conn
	t.info = info

	addr, err := net.ResolveUDPAddr("udp", gnb.GTPuAddr+gtpv1.GTPUPort)
	if err != nil {
		log.Fatalf("failed to net.ResolveUDPAddr: %v", err)
		return
	}
	fmt.Printf("test: gNB UDP local address: %v\n", addr)
	t.uConn = gtpv1.NewUPlaneConn(addr)
	//defer uConn.Close()
	uConn := t.uConn
	if err = uConn.EnableKernelGTP("gtp-gnb", gtpv1.RoleSGSN); err != nil {
		log.Fatalf("failed to EnableKernelGTP: %v", err)
		return
	}

	go func() {
		if err := uConn.ListenAndServe(ctx); err != nil {
			log.Println(err)
			return
		}
		log.Println("uConn.ListenAndServe exited")
	}()

	pdu := gnb.MakeNGSetupRequest()
	t.sendtoAMF(pdu)
	t.recvfromAMF(0)
	return
}

func initRANwithoutSCTP() (t *testSession) {

	t = new(testSession)
	gnb := ngap.NewNGAP("example.json")
	gnb.SetDebugLevel(1)

	t.gnb = gnb

	return
}

func (t *testSession) initUE() {
	t.ue = &t.gnb.UE
	t.ue.PowerON()
	t.ue.SetDebugLevel(1)
	return
}

func (t *testSession) registrateUE() {

	pdu := t.ue.MakeRegistrationRequest()
	t.gnb.RecvfromUE(&pdu)

	buf := t.gnb.MakeInitialUEMessage()
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	pdu = t.ue.MakeAuthenticationResponse()
	t.gnb.RecvfromUE(&pdu)
	buf = t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	pdu = t.ue.MakeSecurityModeComplete()
	t.gnb.RecvfromUE(&pdu)
	buf = t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	buf = t.gnb.MakeInitialContextSetupResponse()
	t.sendtoAMF(buf)

	pdu = t.ue.MakeRegistrationComplete()
	t.gnb.RecvfromUE(&pdu)
	buf = t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)

	// for Configuration Update Command from open5gs AMF.
	t.recvfromAMF(3)
	return
}

func (t *testSession) establishPDUSession() {
	t.ue.PduSessionID()
	t.ue.ProcedureTransactionID()
	pdu := t.ue.MakePDUSessionEstablishmentRequest()
	t.gnb.RecvfromUE(&pdu)
	buf := t.gnb.MakeUplinkNASTransport()
	t.sendtoAMF(buf)
	t.recvfromAMF(0)

	buf = t.gnb.MakePDUSessionResourceSetupResponse()
	t.sendtoAMF(buf)

	return
}

func (t *testSession) setupN3Tunnel() {

	gnb := t.gnb
	ue := t.ue
	uConn := t.uConn
	log.Printf("test: GTPuIFname: %s\n", gnb.GTPuIFname)
	log.Printf("test: GTP-U Peer: %v\n", gnb.Recv.GTPuPeerAddr)
	log.Printf("test: GTP-U Peer TEID: %v\n", gnb.Recv.GTPuPeerTEID)
	log.Printf("test: GTP-U Local TEID: %v\n", gnb.GTPuTEID)
	log.Printf("test: UE address: %v\n", ue.Recv.PDUAddress)

	if err := uConn.AddTunnelOverride(
		gnb.Recv.GTPuPeerAddr, ue.Recv.PDUAddress,
		gnb.Recv.GTPuPeerTEID, gnb.GTPuTEID); err != nil {
		log.Println(err)
		return
	}

	if err := t.addRoute(uConn); err != nil {
		log.Fatalf("failed to addRoute: %v", err)
		return
	}

	err := t.addRuleLocal()
	if err != nil {
		log.Fatalf("failed to addRuleLocal: %v", err)
		return
	}

	//select {
	//case <-ctx.Done():
	//	log.Fatalf("exit gnbsim")
	//}

	return
}
func (t *testSession) delTun() {
	/*	if err := t.uConn.DelTunnelByMSAddress(t.ue.Recv.PDUAddress); err != nil {
			fmt.Println("Cannot delete tunnel")
		}
	*/
	Link := &netlink.GTP{
		LinkAttrs: netlink.LinkAttrs{
			Name: "gtp-gnb",
		},
		//FD1:  int(f.Fd()),
		Role: int(gtpv1.RoleSGSN),
	}
	if err := netlink.LinkDel(Link); err != nil {
		err = fmt.Errorf("failed to DEL tun device=gtp-gnb: %s", err)
		return

	}

}
func (t *testSession) addIP() (err error) {

	gnb := t.gnb
	ue := t.ue

	link, err := netlink.LinkByName(gnb.GTPuIFname)
	if err != nil {
		return err
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	netToAdd := &net.IPNet{
		IP:   ue.Recv.PDUAddress,
		Mask: net.CIDRMask(28, 32),
	}

	var addr netlink.Addr
	var found bool
	for _, a := range addrs {
		if a.Label != gnb.GTPuIFname {
			continue
		}
		found = true
		//fmt.Printf("got=%v, toset=%v\n", a.IPNet.String(), netToAdd.String())
		if a.IPNet.String() == netToAdd.String() {
			return
		}
		addr = a
	}

	if !found {
		err = fmt.Errorf("cannot find the interface to add address: %s",
			gnb.GTPuIFname)
		return
	}

	addr.IPNet = netToAdd
	if err := netlink.AddrAdd(link, &addr); err != nil {
		return err
	}
	return
}

const routeTableID = 1001

func (t *testSession) addRoute(uConn *gtpv1.UPlaneConn) (err error) {

	route := &netlink.Route{
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.CIDRMask(0, 32),
		}, // default route
		LinkIndex: uConn.GTPLink.Attrs().Index, // dev gtp-<ECI>
		Scope:     netlink.SCOPE_LINK,          // scope link
		Protocol:  4,                           // proto static
		Priority:  1,                           // metric 1
		Table:     routeTableID,                // table <ECI>
	}

	err = netlink.RouteReplace(route)
	return
}

func (t *testSession) addRuleLocal() (err error) {

	ue := t.ue

	// 0: NETLINK_ROUTE, no definition found.
	rules, err := netlink.RuleList(0)
	if err != nil {
		return err
	}

	mask32 := &net.IPNet{IP: ue.Recv.PDUAddress, Mask: net.CIDRMask(32, 32)}
	for _, r := range rules {
		if r.Src == mask32 && r.Table == routeTableID {
			return
		}
	}

	rule := netlink.NewRule()
	rule.IifName = "ens3" //interface connect to UE PC
	rule.Src = mask32
	rule.Table = routeTableID
	err = netlink.RuleAdd(rule)

	return
}

func (t *testSession) runUPlane(ctx context.Context) {
	fmt.Printf("runUPlane\n")
	err := t.addRuleLocal()
	if err != nil {
		log.Fatalf("failed to addRuleLocal: %v", err)
		return
	}
	return
}

func (t *testSession) setupCloseHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- !!!gNB stopped!!!")
		t.delTun()
		os.Exit(0)
	}()
}

func main() {

	// usual testing
	ctx, cancel := context.WithCancel(context.Background())
	t := initRAN(ctx)
	defer cancel()
	t.initUE()
	reader := bufio.NewReader(os.Stdin)
	fmt.Println("gnbsim")
	fmt.Println("---------------------")
	fmt.Println("Enter 1,2,3")
	t.setupCloseHandler()
	for {
		fmt.Println("1. UE Registration")
		fmt.Println("2. PDU session setup")
		fmt.Println("3. Stop gNB")
		fmt.Print("-> ")
		text, _ := reader.ReadString('\n')
		// convert CRLF to LF
		text = strings.Replace(text, "\n", "", -1)
		if strings.Compare("1", text) == 0 {
			t.registrateUE()
			time.Sleep(time.Second * 3)
		} else if strings.Compare("2", text) == 0 {
			t.establishPDUSession()
			time.Sleep(time.Second * 3)
			//ctx, cancel := context.WithCancel(context.Background())
			//defer cancel()
			t.setupN3Tunnel()
			time.Sleep(time.Second * 3)
		} else if strings.Compare("3", text) == 0 {
			t.delTun()
			fmt.Println("\r- !!!gNB stopped!!!")
			os.Exit(0)
			//time.Sleep(time.Second * 3)
		}

	}

	return
}
