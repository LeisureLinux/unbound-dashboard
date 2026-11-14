// Package ingestor contains DNS event sources and the shared edge pipeline.
package ingestor

import (
	"unbound-dashboard/core"
)

// Parser is implemented by every data source.
type Parser interface {
	Start(sink core.Sink) error
	GetPath() string
	Close() error
}

// Edge holds the "at the edge" transforms borrowed from DNS-collector:
// normalize → traffic filtering → user privacy, then a configurable block
// policy. Everything happens before a record is handed to the batched writer,
// so filtered/anonymized data is never persisted.
type Edge struct {
	filter *core.DomainFilter
	anon   *core.Anonymizer
	anonOn bool
	codes  map[string]bool
	sink   core.Sink
}

func NewEdge(sink core.Sink, cfg *core.Config, codes map[string]bool) *Edge {
	return &Edge{
		filter: core.NewDomainFilter(cfg.IgnoreDomains),
		anon:   core.NewAnonymizer(),
		anonOn: cfg.AnonymizeIP,
		codes:  codes,
		sink:   sink,
	}
}

// Prepare normalizes, filters and (optionally) anonymizes a record. It is
// called as early as possible so that ignored traffic never enters the
// query/response merger either.
func (e *Edge) Prepare(rec core.QueryRecord) (core.QueryRecord, bool) {
	rec.Domain = core.NormalizeDomain(rec.Domain)
	if rec.Domain == "" {
		core.Metrics.FramesMalformed.Add(1)
		return rec, false
	}
	if e.filter.Ignored(rec.Domain) {
		core.Metrics.RecordsIgnored.Add(1)
		return rec, false
	}
	if e.anonOn {
		rec.ClientIP = e.anon.IP(rec.ClientIP)
	}
	return rec, true
}

// Emit applies the block policy and enqueues the record.
func (e *Edge) Emit(rec core.QueryRecord) {
	rec.Blocked, rec.BlockReason = core.BlockedByPolicy(rec, e.codes)
	if rec.Count < 1 {
		rec.Count = 1
	}
	core.Metrics.FramesParsed.Add(1)
	e.sink.Enqueue(rec)
}
