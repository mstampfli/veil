package launcher

import "strings"

// CountryDefaults returns sensible TZ + lang defaults for an ISO 3166-1
// alpha-2 country code. Used to auto-fingerprint a profile to its
// apparent exit country (e.g. a Mullvad-Switzerland profile gets
// "Europe/Zurich" + "de_CH.UTF-8").
//
// The mapping is intentionally small — just enough to cover common VPN
// exit locations. Unknown countries return zero values; callers should
// keep the user's current TZ/LANG in that case.
func CountryDefaults(cc string) (tz, lang string) {
	cc = strings.ToUpper(strings.TrimSpace(cc))
	tz = countryTZ[cc]
	lang = countryLang[cc]
	return
}

// countryTZ maps ISO country codes to a representative IANA TZ name.
// Multi-zone countries get their capital's zone.
var countryTZ = map[string]string{
	"AU": "Australia/Sydney",
	"AT": "Europe/Vienna",
	"BE": "Europe/Brussels",
	"BG": "Europe/Sofia",
	"BR": "America/Sao_Paulo",
	"CA": "America/Toronto",
	"CH": "Europe/Zurich",
	"CL": "America/Santiago",
	"CN": "Asia/Shanghai",
	"CO": "America/Bogota",
	"CZ": "Europe/Prague",
	"DE": "Europe/Berlin",
	"DK": "Europe/Copenhagen",
	"EE": "Europe/Tallinn",
	"ES": "Europe/Madrid",
	"FI": "Europe/Helsinki",
	"FR": "Europe/Paris",
	"GB": "Europe/London",
	"GR": "Europe/Athens",
	"HK": "Asia/Hong_Kong",
	"HR": "Europe/Zagreb",
	"HU": "Europe/Budapest",
	"ID": "Asia/Jakarta",
	"IE": "Europe/Dublin",
	"IL": "Asia/Jerusalem",
	"IN": "Asia/Kolkata",
	"IS": "Atlantic/Reykjavik",
	"IT": "Europe/Rome",
	"JP": "Asia/Tokyo",
	"KR": "Asia/Seoul",
	"LT": "Europe/Vilnius",
	"LU": "Europe/Luxembourg",
	"LV": "Europe/Riga",
	"MD": "Europe/Chisinau",
	"MX": "America/Mexico_City",
	"MY": "Asia/Kuala_Lumpur",
	"NL": "Europe/Amsterdam",
	"NO": "Europe/Oslo",
	"NZ": "Pacific/Auckland",
	"PH": "Asia/Manila",
	"PL": "Europe/Warsaw",
	"PT": "Europe/Lisbon",
	"RO": "Europe/Bucharest",
	"RS": "Europe/Belgrade",
	"RU": "Europe/Moscow",
	"SE": "Europe/Stockholm",
	"SG": "Asia/Singapore",
	"SI": "Europe/Ljubljana",
	"SK": "Europe/Bratislava",
	"TH": "Asia/Bangkok",
	"TR": "Europe/Istanbul",
	"TW": "Asia/Taipei",
	"UA": "Europe/Kyiv",
	"US": "America/New_York",
	"VN": "Asia/Ho_Chi_Minh",
	"ZA": "Africa/Johannesburg",
}

// countryLang maps ISO country codes to a glibc-style locale id.
var countryLang = map[string]string{
	"AT": "de_AT.UTF-8",
	"AU": "en_AU.UTF-8",
	"BE": "nl_BE.UTF-8",
	"BG": "bg_BG.UTF-8",
	"BR": "pt_BR.UTF-8",
	"CA": "en_CA.UTF-8",
	"CH": "de_CH.UTF-8",
	"CL": "es_CL.UTF-8",
	"CN": "zh_CN.UTF-8",
	"CO": "es_CO.UTF-8",
	"CZ": "cs_CZ.UTF-8",
	"DE": "de_DE.UTF-8",
	"DK": "da_DK.UTF-8",
	"EE": "et_EE.UTF-8",
	"ES": "es_ES.UTF-8",
	"FI": "fi_FI.UTF-8",
	"FR": "fr_FR.UTF-8",
	"GB": "en_GB.UTF-8",
	"GR": "el_GR.UTF-8",
	"HK": "zh_HK.UTF-8",
	"HR": "hr_HR.UTF-8",
	"HU": "hu_HU.UTF-8",
	"ID": "id_ID.UTF-8",
	"IE": "en_IE.UTF-8",
	"IL": "he_IL.UTF-8",
	"IN": "en_IN.UTF-8",
	"IS": "is_IS.UTF-8",
	"IT": "it_IT.UTF-8",
	"JP": "ja_JP.UTF-8",
	"KR": "ko_KR.UTF-8",
	"LT": "lt_LT.UTF-8",
	"LU": "fr_LU.UTF-8",
	"LV": "lv_LV.UTF-8",
	"MD": "ro_MD.UTF-8",
	"MX": "es_MX.UTF-8",
	"MY": "ms_MY.UTF-8",
	"NL": "nl_NL.UTF-8",
	"NO": "nb_NO.UTF-8",
	"NZ": "en_NZ.UTF-8",
	"PH": "en_PH.UTF-8",
	"PL": "pl_PL.UTF-8",
	"PT": "pt_PT.UTF-8",
	"RO": "ro_RO.UTF-8",
	"RS": "sr_RS.UTF-8",
	"RU": "ru_RU.UTF-8",
	"SE": "sv_SE.UTF-8",
	"SG": "en_SG.UTF-8",
	"SI": "sl_SI.UTF-8",
	"SK": "sk_SK.UTF-8",
	"TH": "th_TH.UTF-8",
	"TR": "tr_TR.UTF-8",
	"TW": "zh_TW.UTF-8",
	"UA": "uk_UA.UTF-8",
	"US": "en_US.UTF-8",
	"VN": "vi_VN.UTF-8",
	"ZA": "en_ZA.UTF-8",
}
