//! Rule-providers mihomo: разбор `rule-providers` из `config.yaml` (merge-key `<<`), загрузка
//! payload (inline/file/http, форматы text/yaml/mrs) и индексация под три поведения
//! (`domain`/`ipcidr`/`classical`). Кэш разобранных провайдеров ключуется по (путь, mtime) и
//! вытесняется через 5 минут простоя, чтобы память не росла бесконечно при частых запросах.
//!
//! Семантика соответствия — по `component/trie/domain_set.go` (`DomainSetBuilder`/`DomainSet::Has`)
//! и `rules/provider/{domain,ipcidr,classical}_strategy.go` ветки Alpha MetaCubeX/mihomo:
//! plain-домен матчится ТОЧНО (не как `DOMAIN-SUFFIX`), `.domain`/`+.domain` — как суффикс (`+.`
//! добавляет ещё и точное совпадение), `*.domain` — ровно один произвольный лейбл на месте `*`.

use crate::route_test::cidr::Cidr;
use crate::route_test::dns::Resolver;
use crate::route_test::idle_cache::IdleCache;
use crate::route_test::mihomo::{EvalState, RuleKind, Verdict, parse_predicate};
use crate::ruleset_inspector;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime};
use yaml_rust2::Yaml;
use yaml_rust2::yaml::Hash as YamlHash;

const CACHE_TTL: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Behavior {
    Domain,
    IpCidr,
    Classical,
}

impl Behavior {
    fn as_mihomo_str(self) -> &'static str {
        match self {
            Behavior::Domain => "domain",
            Behavior::IpCidr => "ipcidr",
            Behavior::Classical => "classical",
        }
    }
}

/// Домен-индекс: точное совпадение, суффикс (строгий, без самого домена) и однолейбловый wildcard.
/// Все три структуры хранят исходный текст записи — нужен для поля `detail` ответа.
#[derive(Default)]
pub(crate) struct DomainProvider {
    exact: HashMap<String, String>,
    suffix: HashMap<String, String>,
    wildcard: Vec<(Vec<String>, String)>,
}

impl DomainProvider {
    fn insert(&mut self, raw_line: &str) {
        let line = raw_line.trim();
        if line.is_empty() || line.contains('/') {
            return;
        }
        let lower = line.to_lowercase();
        if let Some(rest) = lower.strip_prefix("+.") {
            if rest.is_empty() {
                return;
            }
            self.exact
                .entry(rest.to_string())
                .or_insert_with(|| raw_line.to_string());
            self.suffix
                .entry(rest.to_string())
                .or_insert_with(|| raw_line.to_string());
        } else if let Some(rest) = lower.strip_prefix('.') {
            if rest.is_empty() {
                return;
            }
            self.suffix
                .entry(rest.to_string())
                .or_insert_with(|| raw_line.to_string());
        } else if lower.contains('*') {
            let labels: Vec<String> = lower.split('.').map(|s| s.to_string()).collect();
            if labels.iter().all(|l| !l.is_empty()) {
                self.wildcard.push((labels, raw_line.to_string()));
            }
        } else if !lower.is_empty() {
            self.exact.entry(lower).or_insert_with(|| raw_line.to_string());
        }
    }

    /// Возвращает исходный текст записи, под которую подпадает домен, если есть совпадение.
    pub(crate) fn matches(&self, domain: &str) -> Option<&str> {
        if let Some(t) = self.exact.get(domain) {
            return Some(t.as_str());
        }
        let mut rest = domain;
        while let Some(idx) = rest.find('.') {
            rest = &rest[idx + 1..];
            if rest.is_empty() {
                break;
            }
            if let Some(t) = self.suffix.get(rest) {
                return Some(t.as_str());
            }
        }
        let labels: Vec<&str> = domain.split('.').collect();
        for (pattern, text) in &self.wildcard {
            if pattern.len() == labels.len() && pattern.iter().zip(labels.iter()).all(|(p, l)| p == "*" || p == l) {
                return Some(text.as_str());
            }
        }
        None
    }
}

#[derive(Default)]
pub(crate) struct IpCidrProvider {
    entries: Vec<(Cidr, String)>,
}

impl IpCidrProvider {
    fn insert(&mut self, raw_line: &str) {
        let trimmed = raw_line.trim();
        if let Some(cidr) = Cidr::parse(trimmed) {
            self.entries.push((cidr, trimmed.to_string()));
        }
    }

    /// Возвращает исходный текст записи, под которую подпадает IP, если есть совпадение.
    pub(crate) fn matches(&self, ip: IpAddr) -> Option<&str> {
        self.entries
            .iter()
            .find(|(cidr, _)| cidr.contains(ip))
            .map(|(_, text)| text.as_str())
    }
}

/// `classical`-провайдер: список строк вида `TYPE,PAYLOAD[,params]` (без цели, см.
/// `classicalStrategy.payloadToRule` в mihomo — `needTarget=false`), объединённых через OR.
/// Храним рядом исходный текст записи — используется в `detail` ответа при совпадении.
#[derive(Default)]
pub(crate) struct ClassicalProvider {
    pub(crate) rules: Vec<(RuleKind, String)>,
}

impl ClassicalProvider {
    /// Возвращает исход и (при совпадении) исходный текст сработавшей строки провайдера.
    pub(crate) async fn matches<R: Resolver>(&self, eval: &mut EvalState<'_, R>) -> (Verdict, Option<String>) {
        let mut saw_unknown: Option<String> = None;
        for (rule, text) in &self.rules {
            match crate::route_test::mihomo::eval_predicate(rule, eval).await {
                Verdict::Match => return (Verdict::Match, Some(text.clone())),
                Verdict::Unknown(reason) => {
                    if saw_unknown.is_none() {
                        saw_unknown = Some(reason);
                    }
                }
                Verdict::NoMatch => {}
            }
        }
        match saw_unknown {
            Some(reason) => (Verdict::Unknown(reason), None),
            None => (Verdict::NoMatch, None),
        }
    }
}

pub(crate) enum ParsedProvider {
    Domain(DomainProvider),
    IpCidr(IpCidrProvider),
    Classical(ClassicalProvider),
}

fn parse_provider_content(content: &str, behavior: Behavior) -> ParsedProvider {
    let lines = extract_rule_lines(content, behavior);
    match behavior {
        Behavior::Domain => {
            let mut p = DomainProvider::default();
            for line in lines {
                p.insert(&line);
            }
            ParsedProvider::Domain(p)
        }
        Behavior::IpCidr => {
            let mut p = IpCidrProvider::default();
            for line in lines {
                p.insert(&line);
            }
            ParsedProvider::IpCidr(p)
        }
        Behavior::Classical => {
            let mut p = ClassicalProvider::default();
            for line in lines {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                if let Ok(node) = parse_predicate(line) {
                    p.rules.push((node, line.to_string()));
                }
            }
            ParsedProvider::Classical(p)
        }
    }
}

/// Достаёт список строк-правил из содержимого файла. `text`/уже сконвертированный из `.mrs` вид —
/// построчно (пропуская пустые строки и комментарии `#`/`//`, как `rulesParse` в mihomo);
/// `yaml` — из ключа `payload:` или `rules:`.
fn extract_rule_lines(content: &str, _behavior: Behavior) -> Vec<String> {
    let trimmed = content.trim_start();
    let looks_like_yaml_key = trimmed.starts_with("payload:") || trimmed.starts_with("rules:");
    if looks_like_yaml_key
        && let Ok(docs) = yaml_rust2::YamlLoader::load_from_str(content)
        && let Some(doc) = docs.first()
    {
        let arr = if !doc["payload"].is_badvalue() {
            doc["payload"].as_vec()
        } else {
            doc["rules"].as_vec()
        };
        if let Some(arr) = arr {
            return arr.iter().filter_map(|v| v.as_str()).map(|s| s.to_string()).collect();
        }
    }
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(|s| s.to_string())
        .collect()
}

/// Разрешает merge-key `<<` (одна мэппинг-запись или список мэппингов), явные ключи побеждают.
/// Псевдонимы (`*anchor`) yaml-rust2 уже разворачивает в клон исходного узла до этой функции.
fn resolve_merge(raw: &YamlHash) -> YamlHash {
    let merge_key = Yaml::String("<<".to_string());
    let mut merged = YamlHash::new();
    if let Some(merge_val) = raw.get(&merge_key) {
        match merge_val {
            Yaml::Hash(h) => {
                for (k, v) in h {
                    merged.entry(k.clone()).or_insert_with(|| v.clone());
                }
            }
            Yaml::Array(items) => {
                for item in items {
                    if let Yaml::Hash(h) = item {
                        for (k, v) in h {
                            merged.entry(k.clone()).or_insert_with(|| v.clone());
                        }
                    }
                }
            }
            _ => {}
        }
    }
    for (k, v) in raw {
        if k == &merge_key {
            continue;
        }
        merged.insert(k.clone(), v.clone());
    }
    merged
}

enum Vehicle {
    Inline(Vec<String>),
    Path(String),
    /// Явно объявлен http/file, но не хватает `url`/`path` (напр. якорь-заготовка) — не ошибка,
    /// просто нечем пользоваться.
    Unusable,
}

pub(crate) struct ProviderDef {
    pub(crate) behavior: Behavior,
    format_mrs: bool,
    vehicle: Vehicle,
}

/// Разбирает мэппинг `rule-providers` верхнего уровня конфига (уже с учётом `<<`).
pub(crate) fn parse_provider_defs(rule_providers: &Yaml, base_dir: &Path) -> HashMap<String, ProviderDef> {
    let mut out = HashMap::new();
    let Some(map) = rule_providers.as_hash() else {
        return out;
    };
    for (name_yaml, raw_def) in map {
        let Some(name) = name_yaml.as_str() else { continue };
        let Yaml::Hash(raw_hash) = raw_def else { continue };
        let merged = resolve_merge(raw_hash);
        let get = |key: &str| -> Option<String> {
            merged
                .get(&Yaml::String(key.to_string()))
                .and_then(|v| v.as_str())
                .map(str::to_string)
        };

        let Some(behavior) = get("behavior").and_then(|b| match b.as_str() {
            "domain" => Some(Behavior::Domain),
            "ipcidr" => Some(Behavior::IpCidr),
            "classical" => Some(Behavior::Classical),
            _ => None,
        }) else {
            continue;
        };
        let format = get("format").unwrap_or_default();
        let format_mrs = format.eq_ignore_ascii_case("mrs");

        let vtype = get("type").unwrap_or_default();
        let vehicle = match vtype.as_str() {
            "inline" => {
                let payload = merged
                    .get(&Yaml::String("payload".to_string()))
                    .and_then(|v| v.as_vec())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(str::to_string)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                if payload.is_empty() {
                    Vehicle::Unusable
                } else {
                    Vehicle::Inline(payload)
                }
            }
            "file" => match get("path") {
                Some(p) => Vehicle::Path(ruleset_inspector::resolve_provider_path_in(
                    &p,
                    &base_dir.to_string_lossy(),
                )),
                None => Vehicle::Unusable,
            },
            "http" => {
                let url = get("url");
                let path = get("path");
                match (path, url) {
                    (Some(p), _) => Vehicle::Path(ruleset_inspector::resolve_provider_path_in(
                        &p,
                        &base_dir.to_string_lossy(),
                    )),
                    (None, Some(u)) => Vehicle::Path(format!("{}/rules/{:x}", base_dir.display(), md5::compute(&u))),
                    (None, None) => Vehicle::Unusable,
                }
            }
            _ => Vehicle::Unusable,
        };

        out.insert(
            name.to_string(),
            ProviderDef {
                behavior,
                format_mrs,
                vehicle,
            },
        );
    }
    out
}

/// Кэш разобранных провайдеров по (путь, mtime) — общий `IdleCache` (см. `idle_cache.rs`), тот же,
/// что и `geodb.rs` использует для `.dat`/`.mmdb`. Смена mtime сама даёт промах (новый ключ), фоновый
/// реапер вытесняет записи без обращений 5 минут.
type ProviderCacheKey = (PathBuf, SystemTime);
static PROVIDER_CACHE: LazyLock<IdleCache<ProviderCacheKey, ParsedProvider>> =
    LazyLock::new(|| IdleCache::new(CACHE_TTL));

/// Загружает и разбирает провайдер, используя кэш по (путь, mtime). Инлайн-провайдеры (без файла)
/// в общий кэш не кладутся — они и так строятся один раз на загрузку движка. Конвертация `.mrs`/
/// чтение файла происходит ДО обращения к кэшу — `IdleCache::insert` не держит блокировку на время
/// IO. Параллельный промах на один и тот же ключ может привести к повторной загрузке — это
/// допустимо (см. `idle_cache.rs`), не пытаемся её схлопывать через single-flight.
async fn load_from_path(path: &str, behavior: Behavior, mrs_behavior: bool) -> Result<Arc<ParsedProvider>, String> {
    let path_buf = PathBuf::from(path);
    let mtime = tokio::fs::metadata(&path_buf)
        .await
        .map_err(|e| format!("файл не найден: {e}"))?
        .modified()
        .map_err(|e| format!("нет mtime: {e}"))?;
    let key = (path_buf, mtime);

    if let Some(cached) = PROVIDER_CACHE.get(&key) {
        return Ok(cached);
    }

    let content = if mrs_behavior {
        ruleset_inspector::convert_mrs(path, behavior.as_mihomo_str()).await?
    } else {
        tokio::fs::read_to_string(&key.0)
            .await
            .map_err(|e| format!("ошибка чтения: {e}"))?
    };
    let parsed = Arc::new(parse_provider_content(&content, behavior));
    PROVIDER_CACHE.insert(key, parsed.clone());
    Ok(parsed)
}

/// Все провайдеры, на которые реально ссылаются правила конфига — держим готовые структуры (не
/// только определения), плюс список имён, недоступных для использования (для варнингов).
pub(crate) struct Providers {
    loaded: HashMap<String, Arc<ParsedProvider>>,
    unusable: HashMap<String, String>,
}

impl Providers {
    pub(crate) async fn load(defs: HashMap<String, ProviderDef>) -> Self {
        let mut loaded = HashMap::new();
        let mut unusable = HashMap::new();
        for (name, def) in defs {
            match def.vehicle {
                Vehicle::Unusable => {
                    unusable.insert(name, "провайдер без url/path/payload".to_string());
                }
                Vehicle::Inline(payload) => {
                    let content = payload.join("\n");
                    loaded.insert(name, Arc::new(parse_provider_content(&content, def.behavior)));
                }
                Vehicle::Path(path) => match load_from_path(&path, def.behavior, def.format_mrs).await {
                    Ok(p) => {
                        loaded.insert(name, p);
                    }
                    Err(e) => {
                        unusable.insert(name, e);
                    }
                },
            }
        }
        Self { loaded, unusable }
    }

    pub(crate) fn get(&self, name: &str) -> Option<&ParsedProvider> {
        self.loaded.get(name).map(|a| a.as_ref())
    }

    pub(crate) fn unusable_reason(&self, name: &str) -> Option<&str> {
        self.unusable.get(name).map(String::as_str)
    }
}
