//! Общая арифметика CIDR для движков mihomo и xray: разбор `addr/bits` и проверка вхождения IP.
//! Совпадение только внутри одного семейства адресов, без разворачивания IPv4-в-IPv6 — как у
//! `netip.Prefix` в стандартной библиотеке Go, которым мihomo и парсит, и матчит `IP-CIDR`/
//! `IP-SUFFIX`/rule-provider `ipcidr` (`rules/common/ipcidr.go`, `rules/common/ipsuffix.go`,
//! `component/cidr::AddIpCidrForString`): "An IPv4 address will not match an IPv6 prefix. An
//! IPv4-mapped IPv6 address will not match an IPv4 prefix" (`net/netip` godoc, `Prefix.Contains`).

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cidr {
    pub(crate) net: IpAddr,
    pub(crate) bits: u8,
}

impl Cidr {
    /// mihomo-семантика: явный `/bits` обязателен (`netip.ParsePrefix` не принимает голый IP) —
    /// используется и для правил `IP-CIDR`/`IP-CIDR6`/`IP-SUFFIX` (плюс их `SRC-*`-варианты), и для
    /// записей rule-provider'ов поведения `ipcidr`.
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let (addr, bits) = raw.split_once('/')?;
        Self::from_parts(addr, bits)
    }

    /// xray-семантика: `"ip": ["1.2.3.4", ...]` допускает голый IP без `/bits`, по умолчанию —
    /// на всю длину адреса (`common/geodata/rule_parser.go::ParseIPRules`). Используется только на
    /// стороне xray.rs — mihomo так делать не должен, поэтому это отдельный, явно иначе названный
    /// конструктор, а не скрытый флаг у `parse`.
    pub(crate) fn parse_or_host(raw: &str) -> Option<Self> {
        match raw.split_once('/') {
            Some((addr, bits)) => Self::from_parts(addr, bits),
            None => {
                let net: IpAddr = raw.trim().parse().ok()?;
                let bits = if net.is_ipv4() { 32 } else { 128 };
                Some(Self { net, bits })
            }
        }
    }

    fn from_parts(addr: &str, bits: &str) -> Option<Self> {
        let net: IpAddr = addr.trim().parse().ok()?;
        let bits: u8 = bits.trim().parse().ok()?;
        let max = if net.is_ipv4() { 32 } else { 128 };
        if bits > max { None } else { Some(Self { net, bits }) }
    }

    /// `true`, если `ip` попадает в сеть. Разные семейства адресов никогда не совпадают (см.
    /// doc-комментарий модуля) — `checked_shl` вместо ручной проверки `bits == 0`: сдвиг на всю
    /// ширину типа (маска для `/0`) в Rust не определён для обычного `<<`, `checked_shl` в этом
    /// случае возвращает `None`, что даёт маску `0`, т.е. «сеть покрывает всё» — ровно то, что
    /// нужно для `/0`.
    pub(crate) fn contains(&self, ip: IpAddr) -> bool {
        match (self.net, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                let mask = u32::MAX.checked_shl(32 - self.bits as u32).unwrap_or(0);
                (u32::from(n) & mask) == (u32::from(i) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                let mask = u128::MAX.checked_shl(128 - self.bits as u32).unwrap_or(0);
                (u128::from(n) & mask) == (u128::from(i) & mask)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_explicit_bits() {
        assert!(Cidr::parse("1.2.3.4").is_none());
        assert!(Cidr::parse("1.2.3.4/32").is_some());
        assert!(Cidr::parse("::1").is_none());
    }

    #[test]
    fn parse_or_host_defaults_bare_ip_to_full_length() {
        let c = Cidr::parse_or_host("1.2.3.4").unwrap();
        assert_eq!(c.bits, 32);
        assert!(c.contains("1.2.3.4".parse().unwrap()));
        assert!(!c.contains("1.2.3.5".parse().unwrap()));

        let c6 = Cidr::parse_or_host("::1").unwrap();
        assert_eq!(c6.bits, 128);
        assert!(c6.contains("::1".parse().unwrap()));
    }

    #[test]
    fn rejects_prefix_longer_than_address_family() {
        assert!(Cidr::parse("1.2.3.4/33").is_none());
        assert!(Cidr::parse("::1/129").is_none());
    }

    #[test]
    fn contains_never_crosses_address_families() {
        let v4 = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(!v4.contains("::1".parse().unwrap()));
        let v6 = Cidr::parse("::/0").unwrap();
        assert!(!v6.contains("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn zero_bits_matches_everything_in_family() {
        let v4 = Cidr::parse("0.0.0.0/0").unwrap();
        assert!(v4.contains("255.255.255.255".parse().unwrap()));
        let v6 = Cidr::parse("::/0").unwrap();
        assert!(v6.contains("ffff::1".parse().unwrap()));
    }

    #[test]
    fn exact_bits_requires_exact_match() {
        let v4 = Cidr::parse("1.2.3.4/32").unwrap();
        assert!(v4.contains("1.2.3.4".parse().unwrap()));
        assert!(!v4.contains("1.2.3.5".parse().unwrap()));
    }

    #[test]
    fn partial_prefix_matches_subnet() {
        let v4 = Cidr::parse("192.168.1.0/24").unwrap();
        assert!(v4.contains("192.168.1.255".parse().unwrap()));
        assert!(!v4.contains("192.168.2.1".parse().unwrap()));
    }
}
