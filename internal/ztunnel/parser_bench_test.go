package ztunnel

import "testing"

func BenchmarkParse(b *testing.B) {
	for _, tc := range fixtures() {
		line := []byte(fixturePrefix + tc.body)
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				_, _, err := Parse(line)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
