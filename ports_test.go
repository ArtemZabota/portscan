package portscan

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestPortSets(t *testing.T) {
	tests := []struct {
		name string
		set  PortSet
		want []uint16
	}{
		{"individual", Ports(443, 80, 443), []uint16{80, 443}},
		{"range", Range(3, 5), []uint16{3, 4, 5}},
		{"union", Union(Range(1, 3), Ports(2, 5), Range(3, 4)), []uint16{1, 2, 3, 4, 5}},
		{"boundaries", Ports(1, 65535), []uint16{1, 65535}},
		{"singleton", Range(65535, 65535), []uint16{65535}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.set.normalize(context.Background())
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("normalize = %v, %v; want %v", got, err, tt.want)
			}
		})
	}
	all, err := Range(1, 65535).normalize(context.Background())
	if err != nil || len(all) != 65535 || all[0] != 1 || all[len(all)-1] != 65535 {
		t.Fatalf("full range: count=%d, err=%v", len(all), err)
	}
}

func TestInvalidPortSets(t *testing.T) {
	for _, set := range []PortSet{
		{}, Ports(), Union(), Ports(0), Ports(-1), Ports(65536),
		Range(1000, 1), Range(0, 1), Range(1, 65536), Range(-2, -1),
		Range(65536, 65536), Union(Ports(80), Range(5, 1)),
	} {
		_, err := set.normalize(context.Background())
		var validation *ValidationError
		if !errors.As(err, &validation) || validation.Field != "ports" {
			t.Errorf("set %v: expected port validation error, got %v", set, err)
		}
	}
}

func TestPortSetsOwnInputs(t *testing.T) {
	input := []int{80, 443}
	set := Ports(input...)
	input[0] = 0
	combined := Union(set, Range(1, 2))
	got, err := combined.normalize(context.Background())
	if err != nil || !reflect.DeepEqual(got, []uint16{1, 2, 80, 443}) {
		t.Fatalf("input mutation changed set: %v, %v", got, err)
	}
	original, _ := set.normalize(context.Background())
	if !reflect.DeepEqual(original, []uint16{80, 443}) {
		t.Fatalf("union mutated its input: %v", original)
	}
}
