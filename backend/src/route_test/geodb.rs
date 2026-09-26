//! Точечные проверки geosite/geoip/geoASN для тестера маршрутов: `.dat` (v2fly/xray protobuf)
//! через целевой поиск тега без полного декодирования файла, `.mmdb`/`.metadb` через крейт
//! `maxminddb` (feature `mmap`). Оба формата отображаются в память через `memmap2` — как и `geo.rs`
//! (тот же паттерн: `File::open` + `unsafe { MmapOptions::new().map(&file) }`), а не читаются
//! целиком в `Vec<u8>` — файлы geo-баз на роутере могут быть по ~10 МБ, и держать их кэшированными
//! (см. ниже) полными копиями в куче накладнее, чем страницами по требованию через mmap.
//!
//! Формат `.dat` (сверено с `common/geodata/geodat.proto` в XTLS/Xray-core):
//! `GeoSiteList{repeated GeoSite entry=1}`, `GeoSite{string code=1; repeated Domain domain=2}`,
//! `Domain{Type type=1 (Substr=0,Regex=1,Domain=2,Full=3); string value=2; repeated Attribute
//! attribute=3}`; `GeoIPList{repeated GeoIP entry=1}`, `GeoIP{string code=1; repeated CIDR cidr=2;
//! bool reverse_match=3}`, `CIDR{bytes ip=1; uint32 prefix=2}`. Тот же формат, что `geo.rs` уже
//! парсит через `find_categories`/`parse_domain_and_match`/`parse_cidr_and_match` — здесь те же
//! типы полей декодируются заново (не переиспользуем `parse_domain_and_match` напрямую), потому что
//! нужно ещё вытащить `attribute` (для `tag@attr`), а трогать сигнатуру фикс-функции в `geo.rs`
//! нельзя. CIDR-матчинг переиспользует `parse_cidr_and_match` — там сравнение битов, без атрибутов.
//!
//! `tag@attr1@attr2` (xray-синтаксис `geosite:google@cn`) разбирается в `site_contains`: `xray.rs`
//! передаёт тег как есть из JSON (`geosite:TAG` или `geosite:TAG@attr`), мы режем по `@`; домен
//! должен иметь ВСЕ перечисленные атрибуты (см. `geodata.AllAttrsMatcher` в Xray-core — это "И",
//! не "ИЛИ"). `ip_in_dat` атрибутов не знает — geoip-правила xray их не поддерживают. Тег и код
//! страны сравниваются без учёта регистра, атрибуты — тоже (в реальных файлах уже lower-case).
//!
//! Кэш: bytes/mmdb-Reader кэшируются по `(path, mtime)` в общем `idle_cache::IdleCache` —
//! вытесняются фоновым tokio-таском, если к записи не обращались 5 минут (на роутере файлы по
//! ~10 МБ, держать их в памяти вечно накладно). Файл читается ДО вставки в кэш, а не под его
//! блокировкой: `IdleCache` держит мьютекс только на само добавление/чтение из `HashMap`, а не на
//! время IO — иначе синхронное чтение файла держало бы стандартный `Mutex` захваченным на потоке
//! tokio-рантайма (в проде `xray.rs`/`mihomo.rs` зовут эти функции из async-хендлера, оборачивая
//! блокирующий вызов в `tokio::task::block_in_place`, а не эта функция).

use crate::geo::parse_cidr_and_match;
use crate::route_test::idle_cache::IdleCache;
use memmap2::{Mmap, MmapOptions};
use prost::bytes::Buf;
use prost::encoding::{DecodeContext, WireType, decode_key, decode_varint, skip_field};
use serde::Deserialize;
use std::fs::{self, File};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};

const IDLE_EVICT: Duration = Duration::from_secs(5 * 60);

type DatCacheKey = (PathBuf, SystemTime);

static DAT_CACHE: LazyLock<IdleCache<DatCacheKey, Mmap>> = LazyLock::new(|| IdleCache::new(IDLE_EVICT));
static MMDB_CACHE: LazyLock<IdleCache<DatCacheKey, maxminddb::Reader<Mmap>>> =
    LazyLock::new(|| IdleCache::new(IDLE_EVICT));

fn file_mtime(path: &Path) -> Result<SystemTime, String> {
    fs::metadata(path)
        .and_then(|m| m.modified())
        .map_err(|e| format!("не удалось прочитать {}: {e}", path.display()))
}

fn load_dat_bytes(path: &Path) -> Result<Arc<Mmap>, String> {
    let mtime = file_mtime(path)?;
    let key = (path.to_path_buf(), mtime);
    if let Some(mmap) = DAT_CACHE.get(&key) {
        return Ok(mmap);
    }
    // Смена mtime сама даёт промах кэша (новый ключ) — старая запись под прежним ключом просто
    // больше не запрашивается и со временем уйдёт по TTL простоя, отдельная инвалидация не нужна.
    let file = File::open(path).map_err(|e| format!("не удалось открыть {}: {e}", path.display()))?;
    // SAFETY: как в `geo.rs` — источник UB у `Mmap::map` в том, что файл может быть усечён или
    // перезаписан другим процессом, пока отображение живо (тогда обращение к «повисшим» страницам
    // — не ошибка чтения, а неопределённое поведение). Здесь это geo-базы из `/opt/etc/mihomo` или
    // `XRAY_ASSET_DIR`, которые обновляются целиком через переименование нового файла поверх старого
    // (`mv`/`rename`), а не переписыванием на месте, так что уже открытое отображение продолжает
    // видеть старое (валидное) содержимое инода, а не половину новых байт.
    let mmap = unsafe { MmapOptions::new().map(&file) }
        .map_err(|e| format!("не удалось отобразить {}: {e}", path.display()))?;
    let mmap = Arc::new(mmap);
    DAT_CACHE.insert(key, mmap.clone());
    Ok(mmap)
}

fn load_mmdb_reader(path: &Path) -> Result<Arc<maxminddb::Reader<Mmap>>, String> {
    let mtime = file_mtime(path)?;
    let key = (path.to_path_buf(), mtime);
    if let Some(reader) = MMDB_CACHE.get(&key) {
        return Ok(reader);
    }
    // SAFETY: то же самое допущение, что и у `load_dat_bytes` выше — обновление базы через
    // переименование файла, а не запись поверх уже открытого.
    let reader = unsafe { maxminddb::Reader::open_mmap(path) }
        .map_err(|e| format!("не удалось открыть {}: {e}", path.display()))?;
    let reader = Arc::new(reader);
    MMDB_CACHE.insert(key, reader.clone());
    Ok(reader)
}

fn read_len_delim<'a>(buf: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = decode_varint(buf).ok()? as usize;
    if buf.remaining() < len {
        return None;
    }
    let slice = &buf[..len];
    buf.advance(len);
    Some(slice)
}

/// Код страны из первого поля (`code`/`country_code` = field 1) записи `GeoSite`/`GeoIP`, без
/// декодирования остальных полей (это и есть "по length-prefix, без полного декода": сами домены
/// или CIDR внутри записи с несовпавшим тегом не парсятся — их пропускает `skip_field`).
fn entry_code<'a>(entry: &mut &'a [u8]) -> &'a str {
    while entry.has_remaining() {
        let Ok((tag, wt)) = decode_key(entry) else { break };
        match (tag, wt) {
            (1, WireType::LengthDelimited) => {
                return read_len_delim(entry)
                    .and_then(|s| std::str::from_utf8(s).ok())
                    .unwrap_or("");
            }
            _ => {
                let _ = skip_field(wt, tag, entry, DecodeContext::default());
            }
        }
    }
    ""
}

/// Ищет в `GeoSiteList`/`GeoIPList` запись с кодом `code` (без учёта регистра) и прогоняет её через
/// `f`. Возвращает `None`, если такого тега в файле нет вообще (не "нет совпадения").
fn find_entry<T>(data: &[u8], code: &str, mut f: impl FnMut(&[u8]) -> T) -> Option<T> {
    let mut buf = data;
    while buf.has_remaining() {
        let Ok((tag, wt)) = decode_key(&mut buf) else { break };
        if tag != 1 || wt != WireType::LengthDelimited {
            let _ = skip_field(wt, tag, &mut buf, DecodeContext::default());
            continue;
        }
        let Some(mut entry) = read_len_delim(&mut buf) else {
            break;
        };
        let entry_for_result = entry;
        if entry_code(&mut entry).eq_ignore_ascii_case(code) {
            return Some(f(entry_for_result));
        }
    }
    None
}

struct GeoDomain<'a> {
    kind: i32,
    value: &'a str,
    attrs: Vec<&'a str>,
}

fn decode_domain(mut buf: &[u8]) -> GeoDomain<'_> {
    let mut d = GeoDomain {
        kind: 0,
        value: "",
        attrs: Vec::new(),
    };
    while buf.has_remaining() {
        let Ok((tag, wt)) = decode_key(&mut buf) else { break };
        match (tag, wt) {
            (1, WireType::Varint) => {
                d.kind = decode_varint(&mut buf).map(|v| v as i32).unwrap_or(0);
            }
            (2, WireType::LengthDelimited) => {
                d.value = read_len_delim(&mut buf)
                    .and_then(|s| std::str::from_utf8(s).ok())
                    .unwrap_or("");
            }
            (3, WireType::LengthDelimited) => {
                if let Some(mut attr) = read_len_delim(&mut buf) {
                    while attr.has_remaining() {
                        let Ok((t, wt)) = decode_key(&mut attr) else { break };
                        if t == 1 && wt == WireType::LengthDelimited {
                            if let Some(key) = read_len_delim(&mut attr).and_then(|s| std::str::from_utf8(s).ok()) {
                                d.attrs.push(key);
                            }
                        } else {
                            let _ = skip_field(wt, t, &mut attr, DecodeContext::default());
                        }
                    }
                }
            }
            _ => {
                let _ = skip_field(wt, tag, &mut buf, DecodeContext::default());
            }
        }
    }
    d
}

fn domain_type_matches(kind: i32, value: &str, dom_low: &str) -> bool {
    match kind {
        0 => dom_low.contains(value),
        1 => regex_lite::Regex::new(value).is_ok_and(|re| re.is_match(dom_low)),
        2 => {
            dom_low == value
                || (dom_low.len() > value.len()
                    && dom_low.ends_with(value)
                    && dom_low.as_bytes()[dom_low.len() - value.len() - 1] == b'.')
        }
        3 => dom_low == value,
        _ => false,
    }
}

/// Разбирает xray-тег `TAG` или `TAG@attr1@attr2` на код страны (верхний регистр канон, сравниваем
/// без учёта регистра) и список обязательных атрибутов (все должны присутствовать на домене).
fn split_tag_attrs(tag: &str) -> (&str, Vec<&str>) {
    let mut parts = tag.split('@');
    let code = parts.next().unwrap_or("");
    (code, parts.collect())
}

/// `true`, если домен подпадает под тег `tag` (опционально `TAG@attr`) в geosite-файле `path`.
pub fn site_contains(path: &Path, tag: &str, domain: &str) -> Result<bool, String> {
    let (code, attrs) = split_tag_attrs(tag);
    if code.is_empty() {
        return Err("пустой тег geosite".into());
    }
    let bytes = load_dat_bytes(path)?;
    let dom_low = domain.to_lowercase();
    find_entry(&bytes, code, |entry| {
        let mut buf = entry;
        while buf.has_remaining() {
            let Ok((tag, wt)) = decode_key(&mut buf) else { break };
            if tag != 2 || wt != WireType::LengthDelimited {
                let _ = skip_field(wt, tag, &mut buf, DecodeContext::default());
                continue;
            }
            let Some(dom_buf) = read_len_delim(&mut buf) else { break };
            let d = decode_domain(dom_buf);
            if !attrs
                .iter()
                .all(|a| d.attrs.iter().any(|da| da.eq_ignore_ascii_case(a)))
            {
                continue;
            }
            if domain_type_matches(d.kind, d.value, &dom_low) {
                return true;
            }
        }
        false
    })
    .ok_or_else(|| format!("тег {code} не найден в {}", path.display()))
}

/// `true`, если IP подпадает под тег `tag` в geoip-файле `path` (учитывает `reverse_match` записи).
pub fn ip_in_dat(path: &Path, tag: &str, ip: IpAddr) -> Result<bool, String> {
    if tag.is_empty() {
        return Err("пустой тег geoip".into());
    }
    let bytes = load_dat_bytes(path)?;
    let (v4, v6) = match ip {
        IpAddr::V4(v4) => (Some(u32::from(v4)), None),
        IpAddr::V6(v6) => (None, Some(u128::from(v6))),
    };
    find_entry(&bytes, tag, |entry| {
        let mut buf = entry;
        let mut reverse = false;
        let mut any_cidr = false;
        while buf.has_remaining() {
            let Ok((t, wt)) = decode_key(&mut buf) else { break };
            match (t, wt) {
                (2, WireType::LengthDelimited) => {
                    if let Some(cidr) = read_len_delim(&mut buf)
                        && !any_cidr
                        && parse_cidr_and_match(cidr, v4, v6)
                    {
                        any_cidr = true;
                    }
                }
                (3, WireType::Varint) => {
                    reverse = decode_varint(&mut buf).map(|v| v != 0).unwrap_or(false);
                }
                _ => {
                    let _ = skip_field(wt, t, &mut buf, DecodeContext::default());
                }
            }
        }
        if reverse { !any_cidr } else { any_cidr }
    })
    .ok_or_else(|| format!("тег {tag} не найден в {}", path.display()))
}

#[derive(Deserialize, Default)]
struct MmdbCountry {
    #[serde(default)]
    iso_code: Option<String>,
}

#[derive(Deserialize, Default)]
struct MmdbCountryRecord {
    #[serde(default)]
    country: MmdbCountry,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum MetaCountryValue {
    One(String),
    Many(Vec<String>),
}

/// Коды стран для IP. Формат базы определяется по `Metadata::database_type`, как в mihomo
/// (`component/mmdb/reader.go`, ветка Alpha): `sing-geoip` — top-level строка, код уже lower-case,
/// не трогаем; `Meta-geoip0` — top-level строка или массив строк, тоже не трогаем регистр;
/// стандартный MaxMind/GeoLite2 — `{country:{iso_code}}`, ISO-коды в этих базах верхнего регистра,
/// приводим к lower-case, чтобы формат совпадал с двумя другими (mihomo делает то же самое).
/// `Ok(None)` — IP не найден в базе вообще; `Ok(Some(vec![]))` — запись есть, но без кода страны.
pub fn mmdb_country(path: &Path, ip: IpAddr) -> Result<Option<Vec<String>>, String> {
    let reader = load_mmdb_reader(path)?;
    let result = reader.lookup(ip).map_err(|e| e.to_string())?;
    if !result.has_data() {
        return Ok(None);
    }
    match reader.metadata().database_type.as_str() {
        "sing-geoip" => {
            let code: Option<String> = result.decode().map_err(|e| e.to_string())?;
            Ok(Some(code.into_iter().collect()))
        }
        "Meta-geoip0" => {
            let value: Option<MetaCountryValue> = result.decode().map_err(|e| e.to_string())?;
            Ok(Some(match value {
                Some(MetaCountryValue::One(s)) => vec![s],
                Some(MetaCountryValue::Many(v)) => v,
                None => Vec::new(),
            }))
        }
        _ => {
            let rec: Option<MmdbCountryRecord> = result.decode().map_err(|e| e.to_string())?;
            Ok(Some(
                rec.and_then(|r| r.country.iso_code)
                    .map(|s| vec![s.to_lowercase()])
                    .unwrap_or_default(),
            ))
        }
    }
}

#[derive(Deserialize, Default)]
struct GeoLite2Asn {
    #[serde(default)]
    autonomous_system_number: u32,
    #[serde(default)]
    autonomous_system_organization: String,
}

#[derive(Deserialize, Default)]
struct IpInfoAsn {
    #[serde(default)]
    asn: String,
    #[serde(default)]
    name: String,
}

enum AsnFormat {
    GeoLite2Compatible,
    IpInfo,
    Unknown,
}

/// `component/mmdb/reader.go::LookupASN` (mihomo, ветка Alpha) распознаёт ASN-базы ПО СПИСКУ, а не
/// "всё, что не ipinfo — считаем GeoLite2": для незнакомого `database_type` mihomo просто
/// варнит и отдаёт пустой результат (`return "", ""`), не пытаясь декодировать чужой формат как
/// GeoLite2 — так и здесь: неизвестный формат даёт `AsnFormat::Unknown` → `mmdb_asn` вернёт `Ok(None)`.
fn detect_asn_format(database_type: &str) -> AsnFormat {
    match database_type {
        "GeoLite2-ASN" | "DBIP-ASN-Lite (compat=GeoLite2-ASN)" => AsnFormat::GeoLite2Compatible,
        "ipinfo generic_asn_free.mmdb" => AsnFormat::IpInfo,
        _ => AsnFormat::Unknown,
    }
}

/// Номер и организация ASN для IP. `GeoLite2-ASN`/совместимые (DB-IP) — поля
/// `autonomous_system_number`/`_organization` напрямую. `ipinfo generic_asn_free.mmdb` — поле `asn`
/// в виде строки `"ASxxxxx"` (mihomo просто режет префикс `AS` и отдаёт строкой; нам нужен номер —
/// парсим остаток в `u32`, при сбое парсинга — 0). Незнакомый `database_type` → `Ok(None)`.
pub fn mmdb_asn(path: &Path, ip: IpAddr) -> Result<Option<(u32, String)>, String> {
    let reader = load_mmdb_reader(path)?;
    let result = reader.lookup(ip).map_err(|e| e.to_string())?;
    if !result.has_data() {
        return Ok(None);
    }
    match detect_asn_format(&reader.metadata().database_type) {
        AsnFormat::GeoLite2Compatible => {
            let rec: Option<GeoLite2Asn> = result.decode().map_err(|e| e.to_string())?;
            Ok(rec.map(|r| (r.autonomous_system_number, r.autonomous_system_organization)))
        }
        AsnFormat::IpInfo => {
            let rec: Option<IpInfoAsn> = result.decode().map_err(|e| e.to_string())?;
            Ok(rec.map(|r| {
                let num = r.asn.strip_prefix("AS").and_then(|s| s.parse().ok()).unwrap_or(0);
                (num, r.name)
            }))
        }
        AsnFormat::Unknown => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn asn_format_recognizes_only_known_database_types() {
        assert!(matches!(
            detect_asn_format("GeoLite2-ASN"),
            AsnFormat::GeoLite2Compatible
        ));
        assert!(matches!(
            detect_asn_format("DBIP-ASN-Lite (compat=GeoLite2-ASN)"),
            AsnFormat::GeoLite2Compatible
        ));
        assert!(matches!(
            detect_asn_format("ipinfo generic_asn_free.mmdb"),
            AsnFormat::IpInfo
        ));
        // Незнакомый формат — не пытаемся угадать по GeoLite2, как раньше (mihomo тоже так не делает).
        assert!(matches!(detect_asn_format("SomeFutureAsnFormat"), AsnFormat::Unknown));
        assert!(matches!(detect_asn_format(""), AsnFormat::Unknown));
    }

    fn varint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                break;
            }
            out.push(byte | 0x80);
        }
    }

    fn tag(field: u32, wire: u8, out: &mut Vec<u8>) {
        varint(((field as u64) << 3) | wire as u64, out);
    }

    fn len_delim(field: u32, payload: &[u8], out: &mut Vec<u8>) {
        tag(field, 2, out);
        varint(payload.len() as u64, out);
        out.extend_from_slice(payload);
    }

    fn encode_domain(kind: i32, value: &str, attrs: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        tag(1, 0, &mut out);
        varint(kind as u64, &mut out);
        len_delim(2, value.as_bytes(), &mut out);
        for a in attrs {
            let mut attr = Vec::new();
            len_delim(1, a.as_bytes(), &mut attr);
            len_delim(3, &attr, &mut out);
        }
        out
    }

    fn encode_geosite(code: &str, domains: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        len_delim(1, code.as_bytes(), &mut out);
        for d in domains {
            len_delim(2, d, &mut out);
        }
        out
    }

    fn encode_geosite_list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            len_delim(1, e, &mut out);
        }
        out
    }

    fn encode_cidr(ip: &[u8], prefix: u32) -> Vec<u8> {
        let mut out = Vec::new();
        len_delim(1, ip, &mut out);
        tag(2, 0, &mut out);
        varint(prefix as u64, &mut out);
        out
    }

    fn encode_geoip(code: &str, cidrs: &[Vec<u8>], reverse: bool) -> Vec<u8> {
        let mut out = Vec::new();
        len_delim(1, code.as_bytes(), &mut out);
        for c in cidrs {
            len_delim(2, c, &mut out);
        }
        if reverse {
            tag(3, 0, &mut out);
            varint(1, &mut out);
        }
        out
    }

    fn encode_geoip_list(entries: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for e in entries {
            len_delim(1, e, &mut out);
        }
        out
    }

    fn write_temp(name: &str, data: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(format!("xkeen-route-test-{name}-{}.dat", std::process::id()));
        let mut f = fs::File::create(&path).unwrap();
        f.write_all(data).unwrap();
        path
    }

    #[test]
    fn site_contains_matches_every_domain_prefix() {
        let google = encode_geosite(
            "GOOGLE",
            &[
                encode_domain(0, "keyword-hit", &[]),
                encode_domain(1, "^regex-[0-9]+$", &[]),
                encode_domain(2, "youtube.com", &[]),
                encode_domain(3, "exact.example.com", &[]),
            ],
        );
        let data = encode_geosite_list(&[google]);
        let path = write_temp("site-prefix", &data);

        assert!(site_contains(&path, "google", "has-keyword-hit-in-it").unwrap());
        assert!(site_contains(&path, "GOOGLE", "regex-42").unwrap());
        assert!(site_contains(&path, "google", "sub.youtube.com").unwrap());
        assert!(site_contains(&path, "google", "youtube.com").unwrap());
        assert!(!site_contains(&path, "google", "notyoutube.com").unwrap());
        assert!(site_contains(&path, "google", "exact.example.com").unwrap());
        assert!(!site_contains(&path, "google", "sub.exact.example.com").unwrap());
        assert!(!site_contains(&path, "google", "unrelated.org").unwrap());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn site_contains_tag_case_insensitive_and_attr_filter() {
        let entry = encode_geosite(
            "ADS",
            &[encode_domain(2, "cn-only.com", &["cn"]), encode_domain(2, "global.com", &[])],
        );
        let data = encode_geosite_list(&[entry]);
        let path = write_temp("site-attr", &data);

        assert!(site_contains(&path, "ads", "global.com").unwrap());
        // Без `@attr` фильтр не применяется — тег матчит все домены категории, включая cn-only.
        assert!(site_contains(&path, "ads", "cn-only.com").unwrap());
        assert!(site_contains(&path, "ADS@cn", "cn-only.com").unwrap());
        assert!(!site_contains(&path, "ads@cn", "global.com").unwrap());
        assert!(!site_contains(&path, "ads@ru", "cn-only.com").unwrap());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn site_contains_unknown_tag_is_error() {
        let data = encode_geosite_list(&[encode_geosite("GOOGLE", &[encode_domain(0, "x", &[])])]);
        let path = write_temp("site-missing-tag", &data);
        assert!(site_contains(&path, "missing", "x.com").is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn ip_in_dat_matches_v4_and_v6_cidr() {
        let v6_prefix: [u8; 16] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let entry = encode_geoip(
            "CN",
            &[encode_cidr(&[1, 2, 3, 0], 24), encode_cidr(&v6_prefix, 32)],
            false,
        );
        let data = encode_geoip_list(&[entry]);
        let path = write_temp("ip-cidr", &data);

        assert!(ip_in_dat(&path, "cn", "1.2.3.4".parse().unwrap()).unwrap());
        assert!(!ip_in_dat(&path, "cn", "1.2.4.4".parse().unwrap()).unwrap());
        assert!(ip_in_dat(&path, "cn", "2001:0db8::1".parse().unwrap()).unwrap());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn ip_in_dat_honors_reverse_match_flag() {
        let entry = encode_geoip("PRIVATE", &[encode_cidr(&[10, 0, 0, 0], 8)], true);
        let data = encode_geoip_list(&[entry]);
        let path = write_temp("ip-reverse", &data);

        assert!(!ip_in_dat(&path, "private", "10.1.2.3".parse().unwrap()).unwrap());
        assert!(ip_in_dat(&path, "private", "8.8.8.8".parse().unwrap()).unwrap());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn ip_in_dat_unknown_tag_is_error() {
        let data = encode_geoip_list(&[encode_geoip("CN", &[encode_cidr(&[1, 1, 1, 1], 32)], false)]);
        let path = write_temp("ip-missing-tag", &data);
        assert!(ip_in_dat(&path, "ru", "1.1.1.1".parse().unwrap()).is_err());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn missing_file_is_error() {
        let path = PathBuf::from("/nonexistent/xkeen-route-test/geosite.dat");
        assert!(site_contains(&path, "google", "youtube.com").is_err());
        assert!(ip_in_dat(&path, "cn", "1.1.1.1".parse().unwrap()).is_err());
        assert!(mmdb_country(&path, "1.1.1.1".parse().unwrap()).is_err());
        assert!(mmdb_asn(&path, "1.1.1.1".parse().unwrap()).is_err());
    }

    /// Ручная проверка на реальных базах: `XKEEN_TEST_MMDB_COUNTRY`/`XKEEN_TEST_MMDB_ASN` — пути к
    /// скачанным `Country.mmdb`/`GeoLite2-ASN.mmdb` (или `geoip.metadb`). Не гоняется в CI.
    #[test]
    #[ignore]
    fn mmdb_country_real_file() {
        let path = std::env::var("XKEEN_TEST_MMDB_COUNTRY").expect("XKEEN_TEST_MMDB_COUNTRY не задан");
        let result = mmdb_country(Path::new(&path), "1.1.1.1".parse().unwrap()).unwrap();
        println!("1.1.1.1 -> {result:?}");
        assert!(result.is_some());
    }

    #[test]
    #[ignore]
    fn mmdb_asn_real_file() {
        let path = std::env::var("XKEEN_TEST_MMDB_ASN").expect("XKEEN_TEST_MMDB_ASN не задан");
        let result = mmdb_asn(Path::new(&path), "1.1.1.1".parse().unwrap()).unwrap();
        println!("1.1.1.1 -> {result:?}");
        assert!(result.is_some());
    }
}
