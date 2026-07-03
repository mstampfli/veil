package validate

import "testing"

func TestName(t *testing.T) {
	good := []string{"alpha", "alpha-1", "alpha_1", "Alpha", "a", "0abc"}
	bad := []string{"", "-leading-dash", "_leading_underscore", "has space",
		"has/slash", "tooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooong"}
	for _, s := range good {
		if err := Name(s); err != nil {
			t.Errorf("Name(%q) unexpected error: %v", s, err)
		}
	}
	for _, s := range bad {
		if err := Name(s); err == nil {
			t.Errorf("Name(%q) expected error, got nil", s)
		}
	}
}

func TestCountry(t *testing.T) {
	good := []string{"", "US", "DE", "JP"}
	bad := []string{"u", "USA", "us", "U.S"}
	for _, s := range good {
		if err := Country(s); err != nil {
			t.Errorf("Country(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := Country(s); err == nil {
			t.Errorf("Country(%q) should fail", s)
		}
	}
}

func TestASN(t *testing.T) {
	good := []string{"", "AS1", "AS9009", "AS123456"}
	bad := []string{"AS", "9009", "as9009", "AS-9009"}
	for _, s := range good {
		if err := ASN(s); err != nil {
			t.Errorf("ASN(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := ASN(s); err == nil {
			t.Errorf("ASN(%q) should fail", s)
		}
	}
}

func TestIP(t *testing.T) {
	good := []string{"", "1.2.3.4", "::1", "2001:db8::1"}
	bad := []string{"1.2.3", "300.1.1.1", "not-an-ip"}
	for _, s := range good {
		if err := IP(s); err != nil {
			t.Errorf("IP(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := IP(s); err == nil {
			t.Errorf("IP(%q) should fail", s)
		}
	}
}

func TestProxyURL(t *testing.T) {
	good := []string{
		"", "socks5://127.0.0.1:9050", "socks5h://127.0.0.1:9050",
		"http://proxy.example:3128", "https://proxy.example:443",
	}
	bad := []string{"ftp://x:21", "http", "socks://nope"}
	for _, s := range good {
		if err := ProxyURL(s); err != nil {
			t.Errorf("ProxyURL(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := ProxyURL(s); err == nil {
			t.Errorf("ProxyURL(%q) should fail", s)
		}
	}
}

func TestAbsPath(t *testing.T) {
	good := []string{"", "/", "/etc/veil"}
	bad := []string{"relative", "/etc/../etc/passwd", "./x"}
	for _, s := range good {
		if err := AbsPath(s); err != nil {
			t.Errorf("AbsPath(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := AbsPath(s); err == nil {
			t.Errorf("AbsPath(%q) should fail", s)
		}
	}
}

func TestScheduleWindow(t *testing.T) {
	good := []string{"", "08:00-22:00", "00:00-23:59", "22:00-06:00"}
	bad := []string{"8-22", "08:00", "25:00-26:00", "08-09"}
	for _, s := range good {
		if err := ScheduleWindow(s); err != nil {
			t.Errorf("ScheduleWindow(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := ScheduleWindow(s); err == nil {
			t.Errorf("ScheduleWindow(%q) should fail", s)
		}
	}
}

func TestLocale(t *testing.T) {
	good := []string{"", "en", "en-US", "de-DE", "en_US.UTF-8", "fr_FR"}
	bad := []string{"english", "EN-US-foo", "123"}
	for _, s := range good {
		if err := Locale(s); err != nil {
			t.Errorf("Locale(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := Locale(s); err == nil {
			t.Errorf("Locale(%q) should fail", s)
		}
	}
}

func TestTimezone(t *testing.T) {
	good := []string{"", "Europe/Berlin", "America/New_York", "UTC"}
	bad := []string{"Mars/Phobos", "not-a-timezone"}
	for _, s := range good {
		if err := Timezone(s); err != nil {
			t.Errorf("Timezone(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := Timezone(s); err == nil {
			t.Errorf("Timezone(%q) should fail", s)
		}
	}
}

func TestPortRange(t *testing.T) {
	good := []string{"", "10000-20000", "32768-60999"}
	bad := []string{"abc", "100-50", "500-600", "10000-x"}
	for _, s := range good {
		if err := PortRange(s); err != nil {
			t.Errorf("PortRange(%q): %v", s, err)
		}
	}
	for _, s := range bad {
		if err := PortRange(s); err == nil {
			t.Errorf("PortRange(%q) should fail", s)
		}
	}
}
