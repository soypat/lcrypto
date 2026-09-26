package cryptobyte

import (
	"testing"
	"time"

	"github.com/soypat/lcrypto/internal/std/cryptobyte/asn1"
)

// refUTCTime and refGeneralizedTime are upstream's ReadASN1UTCTime and
// ReadASN1GeneralizedTime on the element contents.
func refUTCTime(t string) (time.Time, bool) {
	formatStr := "060102150405Z0700"
	res, err := time.Parse(formatStr, t)
	if err != nil {
		formatStr = "0601021504Z0700"
		res, err = time.Parse(formatStr, t)
	}
	if err != nil || res.Format(formatStr) != t {
		return time.Time{}, false
	}
	if res.Year() >= 2050 {
		res = res.AddDate(-100, 0, 0)
	}
	return res, true
}

func refGeneralizedTime(t string) (time.Time, bool) {
	const formatStr = "20060102150405Z0700"
	res, err := time.Parse(formatStr, t)
	if err != nil || res.Format(formatStr) != t {
		return time.Time{}, false
	}
	return res, true
}

func compareTime(t *testing.T, tag asn1.Tag, s string) {
	if len(s) > 127 {
		return
	}
	der := String(append([]byte{byte(tag), byte(len(s))}, s...))
	var got int64
	var ok bool
	var want time.Time
	var wantOK bool
	if tag == asn1.UTCTime {
		ok = der.ReadASN1UTCTimeUnix(&got)
		want, wantOK = refUTCTime(s)
	} else {
		ok = der.ReadASN1GeneralizedTimeUnix(&got)
		want, wantOK = refGeneralizedTime(s)
	}
	if ok != wantOK || ok && got != want.Unix() {
		t.Errorf("%v %q: got %v %v, want %v %v", tag, s, got, ok, want.Unix(), wantOK)
	}
}

var timeCases = []struct {
	tag asn1.Tag
	s   string
}{
	{asn1.UTCTime, "250101000000Z"},
	{asn1.UTCTime, "491231235959Z"},
	{asn1.UTCTime, "500101000000Z"},
	{asn1.UTCTime, "991231235959Z"},
	{asn1.UTCTime, "000229000000Z"},
	{asn1.UTCTime, "010229000000Z"},
	{asn1.UTCTime, "520229000000Z"},
	{asn1.UTCTime, "2501010000Z"},
	{asn1.UTCTime, "250101000060Z"},
	{asn1.UTCTime, "250101240000Z"},
	{asn1.UTCTime, "250101000000+0130"},
	{asn1.UTCTime, "250101000000-2400"},
	{asn1.UTCTime, "250101000000+2500"},
	{asn1.UTCTime, "250101000000+0060"},
	{asn1.UTCTime, "250101000000+0000"},
	{asn1.UTCTime, "250101000000-0000"},
	{asn1.UTCTime, "2501010000+0100"},
	{asn1.UTCTime, "250101000000"},
	{asn1.UTCTime, "250101000000z"},
	{asn1.UTCTime, "25010100000Z"},
	{asn1.UTCTime, "25-101000000Z"},
	{asn1.UTCTime, "251301000000Z"},
	{asn1.UTCTime, "250100000000Z"},
	{asn1.UTCTime, "250431000000Z"},
	{asn1.GeneralizedTime, "20250101000000Z"},
	{asn1.GeneralizedTime, "00000101000000Z"},
	{asn1.GeneralizedTime, "00000229000000Z"},
	{asn1.GeneralizedTime, "19000229000000Z"},
	{asn1.GeneralizedTime, "20000229000000Z"},
	{asn1.GeneralizedTime, "99991231235959Z"},
	{asn1.GeneralizedTime, "20250101000000.5Z"},
	{asn1.GeneralizedTime, "202501010000Z"},
	{asn1.GeneralizedTime, "20250101000000+1000"},
	{asn1.GeneralizedTime, "20250101000000"},
	{asn1.GeneralizedTime, "+2025101000000Z"},
}

func TestReadASN1TimeUnix(t *testing.T) {
	for _, c := range timeCases {
		compareTime(t, c.tag, c.s)
	}
}

func FuzzReadASN1TimeUnix(f *testing.F) {
	for _, c := range timeCases {
		f.Add(c.tag == asn1.UTCTime, c.s)
	}
	f.Fuzz(func(t *testing.T, utc bool, s string) {
		tag := asn1.GeneralizedTime
		if utc {
			tag = asn1.UTCTime
		}
		compareTime(t, tag, s)
	})
}
