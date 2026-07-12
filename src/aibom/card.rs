//! Hugging Face model-card (README.md) extraction.
//!
//! A model card is a Markdown README with a YAML frontmatter block holding
//! structured metadata (license, datasets, base model, pipeline tag, eval
//! results). The YAML is user-authored and frequently dirty, so it is parsed
//! leniently into a [`serde_yaml_ng::Value`] tree first and fields are
//! extracted defensively — a malformed entry drops that field, never the
//! whole card. Everything extracted here is *declared* metadata (the model
//! author's claims), which the builder records as such.

use serde_yaml_ng::Value;

/// Maximum characters of body text captured for a narrative section
/// (limitations, intended use). Model cards can be book-length; the SBOM
/// carries a bounded excerpt plus the model-card URL for the full text.
const MAX_SECTION_CHARS: usize = 600;

/// A single evaluation result from the card's `model-index`.
#[derive(Debug, Clone, PartialEq)]
pub struct CardMetric {
    /// Metric type (e.g. `accuracy`) — falls back to the display name.
    pub metric_type: Option<String>,
    /// Metric value rendered as a string (preserves precision and units).
    pub value: Option<String>,
    /// Dataset the metric was computed on, used as the CycloneDX `slice`.
    pub dataset: Option<String>,
}

/// Structured metadata extracted from a model card.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ModelCard {
    /// HF license tag (e.g. `apache-2.0`, `llama3.1`, `other`).
    pub license: Option<String>,
    /// Custom license display name (`license: other` repos).
    pub license_name: Option<String>,
    /// Custom license URL (`license: other` repos).
    pub license_link: Option<String>,
    /// Training dataset ids declared by the card.
    pub datasets: Vec<String>,
    /// Base model id(s) — more than one implies a merge.
    pub base_model: Vec<String>,
    /// Explicit base-model relation (`adapter`, `merge`, `quantized`,
    /// `finetune`) when declared.
    pub base_model_relation: Option<String>,
    /// Task pipeline tag (e.g. `text-classification`).
    pub pipeline_tag: Option<String>,
    /// Free-form repo tags.
    pub tags: Vec<String>,
    /// Declared languages (ISO 639-1).
    pub languages: Vec<String>,
    /// Library the model targets (e.g. `transformers`).
    pub library_name: Option<String>,
    /// Declared CO2-equivalent emissions in grams, when the card carries the
    /// structured `co2_eq_emissions` block (CO2 is NOT energy — it is kept
    /// separate from `energy_kwh_training`, which HF cards do not declare).
    pub co2_eq_emissions_g: Option<f64>,
    /// Evaluation metrics from `model-index`.
    pub metrics: Vec<CardMetric>,
    /// Bounded excerpt of the card's limitations section(s), when present.
    pub limitations_text: Option<String>,
    /// Bounded excerpt of the card's intended-use section, when present.
    pub intended_use_text: Option<String>,
}

impl ModelCard {
    /// Parse a model card from full README.md content.
    ///
    /// Returns `None` when the README has no YAML frontmatter block at all
    /// (body sections alone are still extracted if frontmatter exists but is
    /// unparseable — an empty card with body excerpts).
    #[must_use]
    pub fn parse(readme: &str) -> Option<Self> {
        let (frontmatter, body) = split_frontmatter(readme)?;
        let mut card = serde_yaml_ng::from_str::<Value>(frontmatter)
            .ok()
            .map(|v| Self::from_yaml(&v))
            .unwrap_or_default();
        card.limitations_text = extract_section(body, &["limitation", "out-of-scope", "bias"]);
        card.intended_use_text = extract_section(body, &["intended use", "direct use", "uses"]);
        Some(card)
    }

    /// Build a card from the Hub API's `cardData` JSON object (the
    /// server-parsed frontmatter). JSON is a YAML subset, so the JSON tree is
    /// re-read as YAML and extracted by the same defensive logic. Body
    /// sections (limitations, intended use) are unavailable via `cardData`.
    #[must_use]
    pub fn from_card_data(card_data: &serde_json::Value) -> Option<Self> {
        if !card_data.is_object() {
            return None;
        }
        let json = serde_json::to_string(card_data).ok()?;
        let yaml = serde_yaml_ng::from_str::<Value>(&json).ok()?;
        Some(Self::from_yaml(&yaml))
    }

    /// Extract fields from a parsed frontmatter tree.
    fn from_yaml(v: &Value) -> Self {
        let mut card = Self {
            license: str_field(v, "license"),
            license_name: str_field(v, "license_name"),
            license_link: str_field(v, "license_link"),
            datasets: str_or_list(v, "datasets"),
            base_model: str_or_list(v, "base_model"),
            base_model_relation: str_field(v, "base_model_relation"),
            pipeline_tag: str_field(v, "pipeline_tag"),
            tags: str_or_list(v, "tags"),
            languages: str_or_list(v, "language"),
            library_name: str_field(v, "library_name"),
            co2_eq_emissions_g: co2_field(v),
            ..Self::default()
        };
        card.metrics = model_index_metrics(v);
        card
    }
}

/// Split `readme` into (frontmatter YAML, body). The frontmatter is the block
/// between a leading `---` line and the next `---`/`...` line.
fn split_frontmatter(readme: &str) -> Option<(&str, &str)> {
    let rest = readme.strip_prefix("---")?;
    // The opening fence must be a bare `---` line.
    let rest = rest.strip_prefix('\r').unwrap_or(rest);
    let rest = rest.strip_prefix('\n')?;
    // Find the closing fence at a line start.
    let mut offset = 0;
    for line in rest.split_inclusive('\n') {
        let trimmed = line.trim_end();
        if trimmed == "---" || trimmed == "..." {
            let yaml = &rest[..offset];
            let body = &rest[offset + line.len()..];
            return Some((yaml, body));
        }
        offset += line.len();
    }
    None
}

/// Read a scalar string field, accepting numbers/booleans rendered verbatim
/// (real cards write `license: 2.0`-style accidents).
fn str_field(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// Read a field that may be a single string or a list of strings.
fn str_or_list(v: &Value, key: &str) -> Vec<String> {
    match v.get(key) {
        Some(Value::String(s)) if !s.trim().is_empty() => vec![s.trim().to_string()],
        Some(Value::Sequence(seq)) => seq
            .iter()
            .filter_map(|item| match item {
                Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_string()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Read `co2_eq_emissions`, which is either a bare number (grams) or a map
/// with an `emissions` number.
fn co2_field(v: &Value) -> Option<f64> {
    match v.get("co2_eq_emissions")? {
        Value::Number(n) => n.as_f64(),
        Value::Mapping(_) => v
            .get("co2_eq_emissions")
            .and_then(|m| m.get("emissions"))
            .and_then(Value::as_f64),
        _ => None,
    }
}

/// Flatten `model-index[].results[].metrics[]` into [`CardMetric`]s.
fn model_index_metrics(v: &Value) -> Vec<CardMetric> {
    let mut out = Vec::new();
    let Some(Value::Sequence(entries)) = v.get("model-index") else {
        return out;
    };
    for entry in entries {
        let Some(Value::Sequence(results)) = entry.get("results") else {
            continue;
        };
        for result in results {
            let dataset = result
                .get("dataset")
                .and_then(|d| d.get("name").or_else(|| d.get("type")))
                .and_then(Value::as_str)
                .map(str::to_string);
            let Some(Value::Sequence(metrics)) = result.get("metrics") else {
                continue;
            };
            for metric in metrics {
                let metric_type = metric
                    .get("type")
                    .or_else(|| metric.get("name"))
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let value = metric.get("value").map(render_scalar);
                if metric_type.is_none() && value.is_none() {
                    continue;
                }
                out.push(CardMetric {
                    metric_type,
                    value,
                    dataset: dataset.clone(),
                });
            }
        }
    }
    out
}

/// Render a YAML scalar (number, string, bool) as a display string.
fn render_scalar(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        other => serde_yaml_ng::to_string(other)
            .unwrap_or_default()
            .trim()
            .to_string(),
    }
}

/// Extract a bounded excerpt of the first Markdown section whose heading
/// contains one of `keywords` (case-insensitive). Captures text until the
/// next heading of any level.
fn extract_section(body: &str, keywords: &[&str]) -> Option<String> {
    let mut lines = body.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        if !trimmed.starts_with('#') {
            continue;
        }
        let heading = trimmed.trim_start_matches('#').trim().to_lowercase();
        if !keywords.iter().any(|k| heading.contains(k)) {
            continue;
        }
        let mut text = String::new();
        for content in lines.by_ref() {
            if content.trim_start().starts_with('#') {
                break;
            }
            let content = content.trim();
            if content.is_empty() {
                if !text.is_empty() {
                    text.push(' ');
                }
                continue;
            }
            if !text.is_empty() && !text.ends_with(' ') {
                text.push(' ');
            }
            text.push_str(content);
            if text.len() >= MAX_SECTION_CHARS {
                break;
            }
        }
        let text = text.trim().to_string();
        if text.is_empty() {
            continue;
        }
        let mut excerpt: String = text.chars().take(MAX_SECTION_CHARS).collect();
        if text.chars().count() > MAX_SECTION_CHARS {
            excerpt.push('…');
        }
        return Some(excerpt);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARD: &str = r#"---
license: apache-2.0
datasets:
- imdb
- glue
base_model: google-bert/bert-base-uncased
pipeline_tag: text-classification
language:
- en
tags:
- sentiment
library_name: transformers
co2_eq_emissions:
  emissions: 42.5
model-index:
- name: demo-sentiment
  results:
  - task:
      type: text-classification
    dataset:
      name: imdb
      type: imdb
    metrics:
    - type: accuracy
      value: 0.928
    - type: f1
      value: 0.93
---

# demo-sentiment

Fine-tuned BERT for sentiment analysis.

## Intended Use

Classify English product reviews as positive or negative.

## Bias, Risks, and Limitations

Trained only on English movie reviews; performance degrades on other
domains and languages.

## Training
"#;

    #[test]
    fn parses_frontmatter_fields() {
        let card = ModelCard::parse(CARD).unwrap();
        assert_eq!(card.license.as_deref(), Some("apache-2.0"));
        assert_eq!(card.datasets, vec!["imdb", "glue"]);
        assert_eq!(card.base_model, vec!["google-bert/bert-base-uncased"]);
        assert_eq!(card.pipeline_tag.as_deref(), Some("text-classification"));
        assert_eq!(card.languages, vec!["en"]);
        assert_eq!(card.co2_eq_emissions_g, Some(42.5));
    }

    #[test]
    fn parses_model_index_metrics() {
        let card = ModelCard::parse(CARD).unwrap();
        assert_eq!(card.metrics.len(), 2);
        assert_eq!(card.metrics[0].metric_type.as_deref(), Some("accuracy"));
        assert_eq!(card.metrics[0].value.as_deref(), Some("0.928"));
        assert_eq!(card.metrics[0].dataset.as_deref(), Some("imdb"));
    }

    #[test]
    fn extracts_body_sections() {
        let card = ModelCard::parse(CARD).unwrap();
        assert!(
            card.limitations_text
                .as_deref()
                .unwrap()
                .contains("English movie reviews")
        );
        assert!(
            card.intended_use_text
                .as_deref()
                .unwrap()
                .contains("product reviews")
        );
    }

    #[test]
    fn scalar_string_fields_survive() {
        let card = ModelCard::parse("---\ndatasets: imdb\nbase_model: [a, b]\n---\nbody").unwrap();
        assert_eq!(card.datasets, vec!["imdb"]);
        assert_eq!(card.base_model, vec!["a", "b"]);
    }

    #[test]
    fn no_frontmatter_is_none() {
        assert!(ModelCard::parse("# Just a readme\n").is_none());
    }

    #[test]
    fn broken_yaml_still_yields_body_sections() {
        let readme = "---\nlicense: [unclosed\n---\n## Limitations\nEnglish only.\n";
        let card = ModelCard::parse(readme).unwrap();
        assert!(card.license.is_none());
        assert_eq!(card.limitations_text.as_deref(), Some("English only."));
    }

    #[test]
    fn bare_co2_number() {
        let card = ModelCard::parse("---\nco2_eq_emissions: 12\n---\n").unwrap();
        assert_eq!(card.co2_eq_emissions_g, Some(12.0));
    }
}
