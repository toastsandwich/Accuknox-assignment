// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadDroper returns the embedded CollectionSpec for droper.
func loadDroper() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_DroperBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load droper: %w", err)
	}

	return spec, err
}

// loadDroperObjects loads droper and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*droperObjects
//	*droperPrograms
//	*droperMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadDroperObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadDroper()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// droperSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type droperSpecs struct {
	droperProgramSpecs
	droperMapSpecs
}

// droperSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type droperProgramSpecs struct {
	XdpDropTcpFunc *ebpf.ProgramSpec `ebpf:"xdp_drop_tcp_func"`
}

// droperMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type droperMapSpecs struct {
}

// droperObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadDroperObjects or ebpf.CollectionSpec.LoadAndAssign.
type droperObjects struct {
	droperPrograms
	droperMaps
}

func (o *droperObjects) Close() error {
	return _DroperClose(
		&o.droperPrograms,
		&o.droperMaps,
	)
}

// droperMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadDroperObjects or ebpf.CollectionSpec.LoadAndAssign.
type droperMaps struct {
}

func (m *droperMaps) Close() error {
	return _DroperClose()
}

// droperPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadDroperObjects or ebpf.CollectionSpec.LoadAndAssign.
type droperPrograms struct {
	XdpDropTcpFunc *ebpf.Program `ebpf:"xdp_drop_tcp_func"`
}

func (p *droperPrograms) Close() error {
	return _DroperClose(
		p.XdpDropTcpFunc,
	)
}

func _DroperClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed droper_bpfel.o
var _DroperBytes []byte
