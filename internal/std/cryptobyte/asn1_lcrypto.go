package cryptobyte

import "github.com/soypat/lcrypto/internal/std/cryptobyte/asn1"

// This file holds allocation free counterparts of readers the port drops:
// upstream's take interface{} or return encoding/asn1 and time types.

// ReadASN1IntegerBytes is ReadASN1Integer for a *[]byte out: it reads a
// non-negative ASN.1 INTEGER as big-endian bytes without leading zeroes, sharing
// memory with s. It avoids ReadASN1Integer's interface parameter.
func (s *String) ReadASN1IntegerBytes(out *[]byte) bool { return s.readASN1Bytes(out) }

// ReadASN1Int64 is ReadASN1Integer for an *int64 out.
func (s *String) ReadASN1Int64(out *int64) bool { return s.readASN1Int64(out) }

// ReadASN1Int is ReadASN1Integer for an *int out: the value must fit int.
func (s *String) ReadASN1Int(out *int) bool {
	var v int64
	if !s.readASN1Int64(&v) || int64(int(v)) != v {
		return false
	}
	*out = int(v)
	return true
}

// ReadASN1Uint is ReadASN1Integer for a *uint out: the value must fit uint.
func (s *String) ReadASN1Uint(out *uint) bool {
	var v uint64
	if !s.readASN1Uint64(&v) || uint64(uint(v)) != v {
		return false
	}
	*out = uint(v)
	return true
}

// ReadOptionalASN1Int is ReadOptionalASN1Integer for an *int out.
func (s *String) ReadOptionalASN1Int(out *int, tag asn1.Tag, defaultValue int) bool {
	var present bool
	var i String
	if !s.ReadOptionalASN1(&i, &present, tag) {
		return false
	}
	if !present {
		*out = defaultValue
		return true
	}
	return i.ReadASN1Int(out) && i.Empty()
}

// ReadASN1BitStringBytes is ReadASN1BitString returning the bytes of the BIT
// STRING, sharing memory with s, and the number of unused bits at its end.
func (s *String) ReadASN1BitStringBytes(out *[]byte, paddingBits *uint8) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.BIT_STRING) || len(bytes) == 0 {
		return false
	}
	padding := bytes[0]
	bytes = bytes[1:]
	if padding > 7 ||
		len(bytes) == 0 && padding != 0 ||
		len(bytes) > 0 && bytes[len(bytes)-1]&(1<<padding-1) != 0 {
		return false
	}
	*out = bytes
	*paddingBits = padding
	return true
}

// ReadASN1ObjectIdentifierBytes is ReadASN1ObjectIdentifier returning the DER
// contents octets of the OBJECT IDENTIFIER, sharing memory with s. It accepts
// exactly the encodings ReadASN1ObjectIdentifier does, so equal identifiers
// have equal bytes.
func (s *String) ReadASN1ObjectIdentifierBytes(out *[]byte) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.OBJECT_IDENTIFIER) || len(bytes) == 0 {
		return false
	}
	oid := bytes
	var v int
	for !bytes.Empty() {
		if !bytes.readBase128Int(&v) {
			return false
		}
	}
	*out = oid
	return true
}

// ReadASN1UTCTimeUnix is ReadASN1UTCTime returning seconds since the Unix epoch.
// Like upstream, which parses with time.Parse and requires the result to format
// back to the input, it accepts YYMMDDhhmm[ss] followed by "Z" or a non-zero
// ±hhmm offset, and reads years 50 to 99 as 1950 to 1999.
func (s *String) ReadASN1UTCTimeUnix(out *int64) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.UTCTime) {
		return false
	}
	yy, ok := digits(bytes, 2)
	if !ok {
		return false
	}
	year := 2000 + yy
	if yy >= 50 {
		year -= 100
	}
	return readTime(bytes[2:], year, true, out)
}

// ReadASN1GeneralizedTimeUnix is ReadASN1GeneralizedTime returning seconds since
// the Unix epoch. It accepts YYYYMMDDhhmmss followed by "Z" or a non-zero ±hhmm
// offset, as upstream's time.Parse round trip does.
func (s *String) ReadASN1GeneralizedTimeUnix(out *int64) bool {
	var bytes String
	if !s.ReadASN1(&bytes, asn1.GeneralizedTime) {
		return false
	}
	year, ok := digits(bytes, 4)
	if !ok {
		return false
	}
	return readTime(bytes[4:], year, false, out)
}

// readTime parses MMDDhhmm[ss](Z|±hhmm) after the year. Seconds are optional
// when optionalSeconds is set.
func readTime(b []byte, year int, optionalSeconds bool, out *int64) bool {
	var f [4]int // month, day, hour, minute
	for i := range f {
		v, ok := digits(b, 2)
		if !ok {
			return false
		}
		f[i], b = v, b[2:]
	}
	sec := 0
	if len(b) >= 2 && isDigit(b[0]) || !optionalSeconds {
		v, ok := digits(b, 2)
		if !ok {
			return false
		}
		sec, b = v, b[2:]
	}
	month, day, hour, minute := f[0], f[1], f[2], f[3]
	if month < 1 || month > 12 || day < 1 || day > daysIn(month, year) ||
		hour > 23 || minute > 59 || sec > 59 {
		return false
	}
	offset := 0
	switch {
	case len(b) == 1 && b[0] == 'Z':
	case len(b) == 5 && (b[0] == '+' || b[0] == '-'):
		hh, ok1 := digits(b[1:], 2)
		mm, ok2 := digits(b[3:], 2)
		// time.Parse allows hours up to 24; Format writes minutes below 60
		// and a zero offset as "Z".
		if !ok1 || !ok2 || hh > 24 || mm > 59 || hh+mm == 0 {
			return false
		}
		offset = (hh*60 + mm) * 60
		if b[0] == '-' {
			offset = -offset
		}
	default:
		return false
	}
	*out = daysFromCivil(year, month, day)*86400 + int64(hour*3600+minute*60+sec-offset)
	return true
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

// digits parses the first n bytes of b as a decimal number.
func digits(b []byte, n int) (int, bool) {
	if len(b) < n {
		return 0, false
	}
	v := 0
	for _, c := range b[:n] {
		if !isDigit(c) {
			return 0, false
		}
		v = v*10 + int(c-'0')
	}
	return v, true
}

func daysIn(month, year int) int {
	switch month {
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

// daysFromCivil returns the number of days from 1970-01-01 to the proleptic
// Gregorian date, after Howard Hinnant's days_from_civil.
func daysFromCivil(y, m, d int) int64 {
	if m <= 2 {
		y--
	}
	era := y // Floor division: y is -1 for January 0000.
	if era < 0 {
		era -= 399
	}
	era /= 400
	yoe := y - era*400
	mp := (m + 9) % 12
	doy := (153*mp+2)/5 + d - 1
	doe := yoe*365 + yoe/4 - yoe/100 + doy
	return int64(era)*146097 + int64(doe) - 719468
}
