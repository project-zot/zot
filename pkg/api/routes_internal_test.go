package api

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRangeHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		header  string
		size    int64
		want    []httpRange
		wantErr bool
	}{
		{
			name:   "open ended range",
			header: "bytes=0-",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "range end is capped to size",
			header: "bytes=0-100",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "suffix range",
			header: "bytes=-3",
			size:   10,
			want:   []httpRange{{start: 7, end: 9}},
		},
		{
			name:   "oversized suffix range returns whole blob",
			header: "bytes=-100",
			size:   10,
			want:   []httpRange{{start: 0, end: 9}},
		},
		{
			name:   "ranges are sorted",
			header: "bytes=7-8, 0-1",
			size:   10,
			want: []httpRange{
				{start: 0, end: 1},
				{start: 7, end: 8},
			},
		},
		{
			name:   "overlapping and adjacent ranges are coalesced",
			header: "bytes=0-2,3-4,6-8,7-9",
			size:   10,
			want: []httpRange{
				{start: 0, end: 4},
				{start: 6, end: 9},
			},
		},
		{name: "zero size", header: "bytes=0-", wantErr: true},
		{name: "wrong unit", header: "byte=0-1", size: 10, wantErr: true},
		{name: "empty range set", header: "bytes=", size: 10, wantErr: true},
		{name: "empty range spec", header: "bytes=0-1,", size: 10, wantErr: true},
		{name: "zero suffix", header: "bytes=-0", size: 10, wantErr: true},
		{name: "bad suffix", header: "bytes=-x", size: 10, wantErr: true},
		{name: "bad start", header: "bytes=x-1", size: 10, wantErr: true},
		{name: "bad end", header: "bytes=1-x", size: 10, wantErr: true},
		{name: "inverted range", header: "bytes=2-1", size: 10, wantErr: true},
		{name: "range starts at size", header: "bytes=10-", size: 10, wantErr: true},
		{name: "range without dash", header: "bytes=0", size: 10, wantErr: true},
		{
			name:    "too many ranges",
			header:  "bytes=" + strings.TrimSuffix(strings.Repeat("0-0,", maxRangeSpecCount+1), ","),
			size:    10,
			wantErr: true,
		},
	}

	for _, test := range tests {
		test := test

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseRangeHeader(test.header, test.size)
			if test.wantErr {
				if err == nil {
					t.Fatal("expected parse error")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected parse error: %v", err)
			}

			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("expected ranges %v, got %v", test.want, got)
			}
		})
	}
}
