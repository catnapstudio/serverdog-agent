package advisories

import "testing"

func TestCompareOrdersVersionsAsDpkgDoes(t *testing.T) {
	for _, pair := range [][2]string{
		{"1.28.3-2ubuntu1.12", "1.28.3-2ubuntu1.13"},
		{"26.2-0ubuntu1~26.04.1", "26.2-0ubuntu1~26.04.2"},
		{"1.0~rc1", "1.0"},
		{"1.0~~", "1.0~"},
		{"1.0", "1.0a"},
		{"1.0a", "1.0+"},
		{"1.0", "1.0.1"},
		{"1.9", "1.10"},
		{"1.0-1", "1.0-1+esm6"},
		{"9:1.0", "10:0.1"},
		{"2.0", "1:1.0"},
		{"7.0.0-30.30", "7.0.0-43.43"},
		{"7.0.0-42.42", "7.0.0-43.43"},
		{"1.14.0-0ubuntu1.11+esm5", "1.14.0-0ubuntu1.11+esm6"},
		{"3.5.5-1ubuntu3.7", "3.5.5-1ubuntu3.10"},
		{"1.0-0", "1.0-0.1"},
		{"0.9", "1.0"},
	} {
		if Compare(pair[0], pair[1]) >= 0 || Compare(pair[1], pair[0]) <= 0 {
			t.Errorf("%s should be older than %s", pair[0], pair[1])
		}
	}

	for _, pair := range [][2]string{{"1.0", "1.0"}, {"0:1.0", "1.0"}, {"1.01", "1.1"}, {"1.0-0", "1.0"}} {
		if Compare(pair[0], pair[1]) != 0 {
			t.Errorf("%s should equal %s", pair[0], pair[1])
		}
	}
}
