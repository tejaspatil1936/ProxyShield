package algorithm

import (
	"math"
	"testing"
)

func TestEntropyEmptyIsZero(t *testing.T) {
	if e := CalculateEntropy(nil); e != 0 {
		t.Errorf("empty input should have entropy 0, got %f", e)
	}
}

func TestEntropyUniformByteIsZero(t *testing.T) {
	data := make([]byte, 256)
	for i := range data {
		data[i] = 'A'
	}
	if e := CalculateEntropy(data); e != 0 {
		t.Errorf("single-symbol input should have entropy 0, got %f", e)
	}
}

func TestEntropyAllBytesEqualIsEight(t *testing.T) {
	// Each of the 256 byte values appears exactly once → maximum entropy of 8.
	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}
	e := CalculateEntropy(data)
	if math.Abs(e-8.0) > 1e-9 {
		t.Errorf("uniform 256-symbol input should have entropy 8, got %f", e)
	}
}

func TestEntropyNaturalTextIsModerate(t *testing.T) {
	text := []byte("the quick brown fox jumps over the lazy dog the quick brown fox")
	e := CalculateEntropy(text)
	if e < 3.0 || e > 5.0 {
		t.Errorf("natural text entropy expected in 3.0-5.0, got %f", e)
	}
}

func TestEntropyHighDiversityExceedsThreshold(t *testing.T) {
	// A wide mixed-alphabet payload should clear the 5.5 WAF threshold.
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()"
	data := make([]byte, 0, 700)
	for i := 0; i < 700; i++ {
		data = append(data, alphabet[i%len(alphabet)])
	}
	if e := CalculateEntropy(data); e < 5.5 {
		t.Errorf("high-diversity payload should exceed 5.5, got %f", e)
	}
}
