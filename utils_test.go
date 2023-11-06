package main

import (
	"testing"
)

func TestXOR(t *testing.T) {
	tc := []struct {
		name string
		a    []byte
		b    []byte
		want []byte
	}{
		{
			name: "equal length",
			a:    []byte{0x01, 0x02, 0x03},
			b:    []byte{0x04, 0x05, 0x06},
			want: []byte{0x05, 0x07, 0x05},
		},
		{
			name: "unequal length",
			a:    []byte{0x01, 0x02, 0x03},
			b:    []byte{0x04, 0x05},
			want: nil,
		},
	}

	for _, c := range tc {
		t.Run(c.name, func(t *testing.T) {
			got, err := xor(c.a, c.b)
			if err != nil {
				if c.want != nil {
					t.Errorf("got %v, want %v", err, c.want)
				}
			} else if string(got) != string(c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}
