package mydispatcher

//go:generate go run github.com/xtls/xray-core/common/errors/errorgen

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	routingSession "github.com/xtls/xray-core/features/routing/session"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"

	"github.com/XrayR-project/XrayR/common/limiter"
	"github.com/XrayR-project/XrayR/common/rule"
)

var errSniffingTimeout = newError("timeout on sniffing")

const freedomProxyConfigType = "xray.proxy.freedom.Config"

type deadlineReader struct {
	r buf.Reader
	c net.Conn
}

func (d deadlineReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return d.r.ReadMultiBuffer()
}

func (d deadlineReader) ReadMultiBufferTimeout(ctx context.Context, dur time.Duration) (buf.MultiBuffer, error) {
	if dur > 0 && d.c != nil {
		_ = d.c.SetReadDeadline(time.Now().Add(dur))
		defer d.c.SetReadDeadline(time.Time{})
	}
	return d.r.ReadMultiBuffer()
}

type deadlineWriter struct {
	w buf.Writer
	c net.Conn
}

func (d deadlineWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	return d.w.WriteMultiBuffer(mb)
}

func (d deadlineWriter) WriteMultiBufferTimeout(ctx context.Context, mb buf.MultiBuffer, dur time.Duration) error {
	if dur > 0 && d.c != nil {
		_ = d.c.SetWriteDeadline(time.Now().Add(dur))
		defer d.c.SetWriteDeadline(time.Time{})
	}
	return d.w.WriteMultiBuffer(mb)
}

type timeoutReader interface {
	buf.Reader
	ReadMultiBufferTimeout(context.Context, time.Duration) (buf.MultiBuffer, error)
}

type timeoutWriter interface {
	buf.Writer
	WriteMultiBufferTimeout(context.Context, buf.MultiBuffer, time.Duration) error
}

type nativeTimeoutReader struct {
	buf.TimeoutReader
}

func (n nativeTimeoutReader) ReadMultiBufferTimeout(ctx context.Context, dur time.Duration) (buf.MultiBuffer, error) {
	return n.TimeoutReader.ReadMultiBufferTimeout(dur)
}

type legacyTimeoutWriter interface {
	buf.Writer
	WriteMultiBufferTimeout(buf.MultiBuffer, time.Duration) error
}

type legacyTimeoutWriterAdapter struct {
	legacyTimeoutWriter
}

func (l legacyTimeoutWriterAdapter) WriteMultiBufferTimeout(ctx context.Context, mb buf.MultiBuffer, dur time.Duration) error {
	return l.legacyTimeoutWriter.WriteMultiBufferTimeout(mb, dur)
}

type connExtractor interface {
	Conn() net.Conn
}

type rawConnExtractor interface {
	RawConn() net.Conn
}

type netConnExtractor interface {
	NetConn() net.Conn
}

type underlyingConnExtractor interface {
	UnderlyingConn() net.Conn
}

type cachedReader struct {
	sync.Mutex
	reader timeoutReader
	cache  buf.MultiBuffer
}

func extractNetConnFromLink(ctx context.Context, link *transport.Link) net.Conn {
	if link != nil {
		if conn := extractNetConn(link.Reader); conn != nil {
			return conn
		}
		if conn := extractNetConn(link.Writer); conn != nil {
			return conn
		}
	}
	if ctx == nil {
		return nil
	}
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		if inbound.Conn != nil {
			return inbound.Conn
		}
	}
	if outbounds := session.OutboundsFromContext(ctx); len(outbounds) > 0 {
		if obConn := outbounds[len(outbounds)-1].Conn; obConn != nil {
			return obConn
		}
	}
	return nil
}

func extractNetConn(target interface{}) net.Conn {
	switch v := target.(type) {
	case connExtractor:
		return v.Conn()
	case rawConnExtractor:
		return v.RawConn()
	case netConnExtractor:
		return v.NetConn()
	case underlyingConnExtractor:
		return v.UnderlyingConn()
	case interface{ SystemConn() net.Conn }:
		return v.SystemConn()
	case interface{ AsConn() net.Conn }:
		return v.AsConn()
	case interface{ Conn() *net.TCPConn }:
		return v.Conn()
	case interface{ TCPConn() *net.TCPConn }:
		return v.TCPConn()
	default:
		return nil
	}
}

func selectTimeoutReader(ctx context.Context, link *transport.Link) timeoutReader {
	if link == nil || link.Reader == nil {
		return nil
	}
	if tr, ok := link.Reader.(timeoutReader); ok {
		errors.LogDebug(ctx, "vision: reader using native timeout reader")
		return tr
	}
	if tr, ok := link.Reader.(buf.TimeoutReader); ok {
		errors.LogDebug(ctx, "vision: reader using buf.TimeoutReader")
		return nativeTimeoutReader{TimeoutReader: tr}
	}
	conn := extractNetConnFromLink(ctx, link)
	if conn != nil {
		errors.LogDebug(ctx, "vision: reader using deadlineReader with net.Conn")
	} else {
		errors.LogDebug(ctx, "vision: reader using deadlineReader without net.Conn")
	}
	return deadlineReader{r: link.Reader, c: conn}
}

func selectTimeoutWriter(ctx context.Context, link *transport.Link) timeoutWriter {
	if link == nil || link.Writer == nil {
		return nil
	}
	if tw, ok := link.Writer.(timeoutWriter); ok {
		errors.LogDebug(ctx, "vision: writer using native timeout writer")
		return tw
	}
	if tw, ok := link.Writer.(legacyTimeoutWriter); ok {
		errors.LogDebug(ctx, "vision: writer using legacy timeout writer")
		return legacyTimeoutWriterAdapter{legacyTimeoutWriter: tw}
	}
	conn := extractNetConnFromLink(ctx, link)
	if conn != nil {
		errors.LogDebug(ctx, "vision: writer using deadlineWriter with net.Conn")
	} else {
		errors.LogDebug(ctx, "vision: writer using deadlineWriter without net.Conn")
	}
	return deadlineWriter{w: link.Writer, c: conn}
}

func closeLinkWriter(ctx context.Context, link *transport.Link) {
	if link == nil || link.Writer == nil {
		return
	}
	if conn := extractNetConnFromLink(ctx, link); conn != nil {
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
	}
	if closer, ok := link.Writer.(interface{ CloseWrite() error }); ok {
		_ = closer.CloseWrite()
	}
	common.Close(link.Writer)
}

func (r *cachedReader) Cache(ctx context.Context, b *buf.Buffer, deadline time.Duration) error {
	mb, err := r.reader.ReadMultiBufferTimeout(ctx, deadline)
	if err != nil {
		return err
	}
	r.Lock()
	if !mb.IsEmpty() {
		r.cache, _ = buf.MergeMulti(r.cache, mb)
	}
	b.Clear()
	cap := int32(b.Cap())
	if l := int32(r.cache.Len()); l < cap {
		cap = l
	}
	rawBytes := b.Extend(cap)
	n := r.cache.Copy(rawBytes)
	b.Resize(0, int32(n))
	r.Unlock()
	return nil
}

func (r *cachedReader) readInternal() buf.MultiBuffer {
	r.Lock()
	defer r.Unlock()

	if r.cache != nil && !r.cache.IsEmpty() {
		mb := r.cache
		r.cache = nil
		return mb
	}

	return nil
}

func (r *cachedReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBuffer()
}

func (r *cachedReader) ReadMultiBufferTimeout(ctx context.Context, timeout time.Duration) (buf.MultiBuffer, error) {
	mb := r.readInternal()
	if mb != nil {
		return mb, nil
	}

	return r.reader.ReadMultiBufferTimeout(ctx, timeout)
}

func (r *cachedReader) Interrupt() {
	r.Lock()
	if r.cache != nil {
		r.cache = buf.ReleaseMulti(r.cache)
	}
	r.Unlock()
	common.Interrupt(r.reader)
}

// DefaultDispatcher is a default implementation of Dispatcher.
type DefaultDispatcher struct {
	ohm         outbound.Manager
	router      routing.Router
	policy      policy.Manager
	stats       stats.Manager
	fdns        dns.FakeDNSEngine
	Limiter     *limiter.Limiter
	RuleManager *rule.Manager
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		d := new(DefaultDispatcher)
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager) error {
			core.OptionalFeatures(ctx, func(fdns dns.FakeDNSEngine) {
				d.fdns = fdns
			})
			return d.Init(config.(*Config), om, router, pm, sm)
		}); err != nil {
			return nil, err
		}
		return d, nil
	}))
}

// Init initializes DefaultDispatcher.
func (d *DefaultDispatcher) Init(config *Config, om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager) error {
	d.ohm = om
	d.router = router
	d.policy = pm
	d.stats = sm
	d.Limiter = limiter.New()
	d.RuleManager = rule.New()
	return nil
}

// Type implements common.HasType.
func (*DefaultDispatcher) Type() interface{} {
	return routing.DispatcherType()
}

// Start implements common.Runnable.
func (*DefaultDispatcher) Start() error {
	return nil
}

// Close implements common.Closable.
func (*DefaultDispatcher) Close() error {
	return nil
}

func (d *DefaultDispatcher) getLink(ctx context.Context) (*transport.Link, *transport.Link, error) {
	opt := pipe.OptionsFromContext(ctx)
	uplinkReader, uplinkWriter := pipe.New(opt...)
	downlinkReader, downlinkWriter := pipe.New(opt...)

	inboundLink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	outboundLink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	sessionInbound := session.InboundFromContext(ctx)
	var user *protocol.MemoryUser
	if sessionInbound != nil {
		user = sessionInbound.User
	}

	if user != nil && len(user.Email) > 0 {
		// Speed Limit and Device Limit
		bucket, ok, reject := d.Limiter.GetUserBucket(sessionInbound.Tag, user.Email, sessionInbound.Source.Address.IP().String())
		if reject {
			errors.LogWarning(ctx, "Devices reach the limit: ", user.Email)
			closeLinkWriter(ctx, outboundLink)
			closeLinkWriter(ctx, inboundLink)
			common.Interrupt(outboundLink.Reader)
			common.Interrupt(inboundLink.Reader)
			return nil, nil, newError("Devices reach the limit: ", user.Email)
		}
		if ok {
			inboundLink.Writer = d.Limiter.RateWriter(inboundLink.Writer, bucket)
			outboundLink.Writer = d.Limiter.RateWriter(outboundLink.Writer, bucket)
		}

		p := d.policy.ForLevel(user.Level)
		if p.Stats.UserUplink {
			name := "user>>>" + user.Email + ">>>traffic>>>uplink"
			if c, _ := stats.GetOrRegisterCounter(d.stats, name); c != nil {
				inboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  inboundLink.Writer,
				}
			}
		}
		if p.Stats.UserDownlink {
			name := "user>>>" + user.Email + ">>>traffic>>>downlink"
			if c, _ := stats.GetOrRegisterCounter(d.stats, name); c != nil {
				outboundLink.Writer = &SizeStatWriter{
					Counter: c,
					Writer:  outboundLink.Writer,
				}
			}
		}
	}

	return inboundLink, outboundLink, nil
}

func (d *DefaultDispatcher) shouldOverride(ctx context.Context, result SniffResult, request session.SniffingRequest, destination xnet.Destination) bool {
	domain := result.Domain()
	if domain == "" {
		return false
	}
	domainLower := strings.ToLower(domain)
	for _, d := range request.ExcludeForDomain {
		if strings.HasPrefix(d, "regexp:") {
			pattern := d[7:]
			re, err := regexp.Compile(pattern)
			if err != nil {
				errors.LogInfo(ctx, "Unable to compile regex")
				continue
			}
			if re.MatchString(domain) {
				return false
			}
		} else if domainLower == d {
			return false
		}
	}
	protocolString := result.Protocol()
	if resComp, ok := result.(SnifferResultComposite); ok {
		protocolString = resComp.ProtocolForDomainResult()
	}
	for _, p := range request.OverrideDestinationForProtocol {
		if strings.HasPrefix(protocolString, p) || strings.HasPrefix(p, protocolString) {
			return true
		}
		if fkr0, ok := d.fdns.(dns.FakeDNSEngineRev0); ok && protocolString != "bittorrent" && p == "fakedns" &&
			destination.Address.Family().IsIP() && fkr0.IsIPInIPPool(destination.Address) {
			errors.LogInfo(ctx, "Using sniffer ", protocolString, " since the fake DNS missed")
			return true
		}
		if resultSubset, ok := result.(SnifferIsProtoSubsetOf); ok {
			if resultSubset.IsProtoSubsetOf(p) {
				return true
			}
		}
	}

	return false
}

// Dispatch implements routing.Dispatcher.
func (d *DefaultDispatcher) Dispatch(ctx context.Context, destination xnet.Destination) (*transport.Link, error) {
	if !destination.IsValid() {
		panic("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}

	sniffingRequest := content.SniffingRequest
	inbound, outbound, err := d.getLink(ctx)
	if err != nil {
		return nil, err
	}
	readerWrapper := selectTimeoutReader(ctx, outbound)
	if readerWrapper == nil {
		readerWrapper = deadlineReader{
			r: outbound.Reader,
			c: extractNetConnFromLink(ctx, outbound),
		}
	}
	outbound.Reader = readerWrapper
	if writerWrapper := selectTimeoutWriter(ctx, outbound); writerWrapper != nil {
		outbound.Writer = writerWrapper
	}
	if !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination)
	} else {
		go func(reader timeoutReader) {
			cReader := &cachedReader{
				reader: reader,
			}
			outbound.Reader = cReader
			result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
			if err == nil {
				content.Protocol = result.Protocol()
			}
			if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
				domain := result.Domain()
				errors.LogInfo(ctx, "sniffed domain: ", domain)
				destination.Address = xnet.ParseAddress(domain)
				if sniffingRequest.RouteOnly && result.Protocol() != "fakedns" {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
			d.routedDispatch(ctx, outbound, destination)
		}(readerWrapper)
	}
	return inbound, nil
}

// DispatchLink implements routing.Dispatcher.
func (d *DefaultDispatcher) DispatchLink(ctx context.Context, destination xnet.Destination, outbound *transport.Link) error {
	if !destination.IsValid() {
		return newError("Dispatcher: Invalid destination.")
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	ob := outbounds[len(outbounds)-1]
	ob.OriginalTarget = destination
	ob.Target = destination
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	sniffingRequest := content.SniffingRequest

	readerWrapper := selectTimeoutReader(ctx, outbound)
	if readerWrapper == nil {
		readerWrapper = deadlineReader{
			r: outbound.Reader,
			c: extractNetConnFromLink(ctx, outbound),
		}
	}
	outbound.Reader = readerWrapper
	if writerWrapper := selectTimeoutWriter(ctx, outbound); writerWrapper != nil {
		outbound.Writer = writerWrapper
	}
	if !sniffingRequest.Enabled {
		go d.routedDispatch(ctx, outbound, destination)
	} else {
		go func(reader timeoutReader) {
			cReader := &cachedReader{
				reader: reader,
			}
			outbound.Reader = cReader
			result, err := sniffer(ctx, cReader, sniffingRequest.MetadataOnly, destination.Network)
			if err == nil {
				content.Protocol = result.Protocol()
			}
			if err == nil && d.shouldOverride(ctx, result, sniffingRequest, destination) {
				domain := result.Domain()
				errors.LogInfo(ctx, "sniffed domain: ", domain)
				destination.Address = xnet.ParseAddress(domain)
				if sniffingRequest.RouteOnly && result.Protocol() != "fakedns" {
					ob.RouteTarget = destination
				} else {
					ob.Target = destination
				}
			}
			d.routedDispatch(ctx, outbound, destination)
		}(readerWrapper)
	}

	return nil
}

func sniffer(ctx context.Context, cReader *cachedReader, metadataOnly bool, network xnet.Network) (SniffResult, error) {
	payload := buf.NewWithSize(32767)
	defer payload.Release()

	sniffer := NewSniffer(ctx)

	metaresult, metadataErr := sniffer.SniffMetadata(ctx)

	if metadataOnly {
		return metaresult, metadataErr
	}

	contentResult, contentErr := func() (SniffResult, error) {
		cacheDeadline := 200 * time.Millisecond
		totalAttempt := 0
		for {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
				cachingStartingTimeStamp := time.Now()
				if err := cReader.Cache(ctx, payload, cacheDeadline); err != nil {
					return nil, err
				}
				cachingTimeElapsed := time.Since(cachingStartingTimeStamp)
				cacheDeadline -= cachingTimeElapsed

				if !payload.IsEmpty() {
					result, err := sniffer.Sniff(ctx, payload.Bytes(), network)
					switch err {
					case common.ErrNoClue:
						totalAttempt++
					case protocol.ErrProtoNeedMoreData:
						return nil, err
					default:
						return result, err
					}
				} else {
					totalAttempt++
				}
				if totalAttempt >= 2 || cacheDeadline <= 0 {
					return nil, errSniffingTimeout
				}
			}
		}
	}()
	if contentErr != nil && metadataErr == nil {
		return metaresult, nil
	}
	if contentErr == nil && metadataErr == nil {
		return CompositeResult(metaresult, contentResult), nil
	}
	return contentResult, contentErr
}

func (d *DefaultDispatcher) routedDispatch(ctx context.Context, link *transport.Link, destination xnet.Destination) {
	var handler outbound.Handler

	// Check if domain and protocol hit the rule
	sessionInbound := session.InboundFromContext(ctx)
	// Whether the inbound connection contains a user
	if sessionInbound.User != nil {
		if d.RuleManager.Detect(sessionInbound.Tag, destination.String(), sessionInbound.User.Email) {
			errors.LogError(ctx, fmt.Sprintf("User %s access %s reject by rule", sessionInbound.User.Email, destination.String()))
			newError("destination is reject by rule")
			closeLinkWriter(ctx, link)
			common.Interrupt(link.Reader)
			return
		}
	}

	routingLink := routingSession.AsRoutingContext(ctx)
	inTag := routingLink.GetInboundTag()
	isPickRoute := 0
	if forcedOutboundTag := session.GetForcedOutboundTagFromContext(ctx); forcedOutboundTag != "" {
		ctx = session.SetForcedOutboundTagToContext(ctx, "")
		if h := d.ohm.GetHandler(forcedOutboundTag); h != nil {
			isPickRoute = 1
			errors.LogInfo(ctx, "taking platform initialized detour [", forcedOutboundTag, "] for [", destination, "]")
			handler = h
		} else {
			errors.LogError(ctx, "non existing tag for platform initialized detour: ", forcedOutboundTag)
			closeLinkWriter(ctx, link)
			common.Interrupt(link.Reader)
			return
		}
	} else if d.router != nil {
		if route, err := d.router.PickRoute(routingLink); err == nil {
			outTag := route.GetOutboundTag()
			if h := d.ohm.GetHandler(outTag); h != nil {
				isPickRoute = 2
				errors.LogInfo(ctx, "taking detour [", outTag, "] for [", destination, "]")
				handler = h
			} else {
				errors.LogWarning(ctx, "non existing outTag: ", outTag)
			}
		} else {
			errors.LogInfo(ctx, "default route for ", destination)
		}
	}

	if handler == nil {
		handler = d.ohm.GetHandler(inTag) // Default outbound handler tag should be as same as the inbound tag
	}

	// If there is no outbound with tag as same as the inbound tag
	if handler == nil {
		handler = d.ohm.GetDefaultHandler()
	}

	if handler == nil {
		errors.LogInfo(ctx, "default outbound handler not exist")
		closeLinkWriter(ctx, link)
		common.Interrupt(link.Reader)
		return
	}

	if accessMessage := log.AccessMessageFromContext(ctx); accessMessage != nil {
		if tag := handler.Tag(); tag != "" {
			if inTag == "" {
				accessMessage.Detour = tag
			} else if isPickRoute == 1 {
				accessMessage.Detour = inTag + " ==> " + tag
			} else if isPickRoute == 2 {
				accessMessage.Detour = inTag + " -> " + tag
			} else {
				accessMessage.Detour = inTag + " >> " + tag
			}
		}
		log.Record(accessMessage)
	}

	dispatchCtx := ctx
	if settings := handler.ProxySettings(); settings != nil && settings.Type == freedomProxyConfigType {
		baseCtx := context.WithoutCancel(ctx)
		dispatchCtx, dcancel := context.WithTimeout(baseCtx, 10*time.Second)
		defer dcancel()
		errors.LogDebug(dispatchCtx, "vision: freedom dispatch start")
		defer errors.LogDebug(dispatchCtx, "vision: freedom dispatch done")
		defer func() {
			if r := recover(); r != nil {
				errors.LogWarning(dispatchCtx, "vision: freedom dispatch panic: %v", r)
				panic(r)
			}
		}()
	}
	handler.Dispatch(dispatchCtx, link)
}
