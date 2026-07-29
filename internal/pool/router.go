package pool

import "time"

// exitSampleDebounce bounds how often one instance's exit relay is re-read while
// connections are arriving, so a burst costs a single control-port query.
const exitSampleDebounce = 2 * time.Second

// RouteAddr resolves a session to the SOCKS address of its instance.
//
// The proxy layer is given an address rather than an instance so it cannot hold
// a reference to something the pool may retire underneath it.
func (p *Pool) RouteAddr(sessionKey string) (instance int, socksAddr string, err error) {
	inst, err := p.Route(sessionKey)
	if err != nil {
		return 0, "", err
	}
	cfg := inst.Config()
	return inst.Index(), cfg.SocksAddr(), nil
}

// RecordTransportFailure attributes a transport-level failure to an instance.
//
// Transport failures are what the balancer can see for itself: a refused SOCKS
// handshake, a reset, a timeout. They are blind to HTTP-level blocking, which is
// why ReportFailure exists alongside this — and why the balancer can only ever
// report KindTransport, whatever the request was actually answered with.
func (p *Pool) RecordTransportFailure(instance int, reason string) {
	p.log.Debug("transport failure", "instance", instance, "reason", reason)
	p.RecordFailure(instance, SourceTransport, KindTransport, reason)
}

// SampleExit re-reads an instance's exit relay, debounced per instance.
//
// The proxy layer calls this shortly after establishing a connection, because
// that is the only moment tor can say which circuit is actually carrying the
// traffic. Between requests there is no attached stream and the answer degrades
// to a guess.
func (p *Pool) SampleExit(instance int) {
	now := time.Now()

	p.sampleMu.Lock()
	if last, ok := p.lastExitSample[instance]; ok && now.Sub(last) < exitSampleDebounce {
		p.sampleMu.Unlock()
		return
	}
	p.lastExitSample[instance] = now
	p.sampleMu.Unlock()

	inst, ok := p.fleet.Get(instance)
	if !ok {
		return
	}
	if _, err := inst.RefreshExitNode(); err != nil {
		p.log.Debug("exit sample failed", "instance", instance, "error", err)
	}
}
