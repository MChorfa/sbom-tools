//! `config.json` / `adapter_config.json` extraction.
//!
//! `config.json` is the transformers model configuration — the most reliable
//! *computed-adjacent* metadata in a repo (it drives actual model loading, so
//! it is far less prone to drift than the model card). Only fields with a
//! defined AIBOM mapping are extracted.

use serde_json::Value;

/// Hyperparameters surfaced as `cdx:ai-ml:model:hyperparameter:*` properties.
/// Property names follow the CycloneDX AI/ML property-taxonomy spelling.
const HYPERPARAMETER_KEYS: &[(&str, &str)] = &[
    ("max_position_embeddings", "context_length"),
    ("vocab_size", "vocab_size"),
    ("num_hidden_layers", "num_hidden_layers"),
    ("hidden_size", "hidden_size"),
    ("num_attention_heads", "num_attention_heads"),
];

/// Extracted transformers model configuration.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ModelConfig {
    /// Architecture family key (e.g. `llama`, `bert`).
    pub model_type: Option<String>,
    /// Concrete architecture class (e.g. `BertForSequenceClassification`).
    pub architecture: Option<String>,
    /// Weight dtype: transformers ≤4 `torch_dtype`, v5-era `dtype`.
    pub dtype: Option<String>,
    /// Quantization method from `quantization_config.quant_method`
    /// (e.g. `gptq`, `awq`, `bitsandbytes`).
    pub quantization: Option<String>,
    /// Selected hyperparameters as (taxonomy name, value) pairs.
    pub hyperparameters: Vec<(String, String)>,
    /// `auto_map` present — the repo ships custom Python code that
    /// `trust_remote_code` would execute.
    pub has_custom_code: bool,
    /// transformers version the config was written by.
    pub transformers_version: Option<String>,
}

impl ModelConfig {
    /// Parse from `config.json` content. Returns `None` for unparseable JSON
    /// (the file is then still inventoried as a plain config file).
    #[must_use]
    pub fn parse(content: &str) -> Option<Self> {
        let v: Value = serde_json::from_str(content).ok()?;
        let obj = v.as_object()?;

        let hyperparameters = HYPERPARAMETER_KEYS
            .iter()
            .filter_map(|(key, taxonomy_name)| {
                obj.get(*key)
                    .and_then(Value::as_u64)
                    .map(|n| ((*taxonomy_name).to_string(), n.to_string()))
            })
            .collect();

        Some(Self {
            model_type: str_field(obj.get("model_type")),
            architecture: obj
                .get("architectures")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(Value::as_str)
                .map(str::to_string),
            dtype: str_field(obj.get("torch_dtype")).or_else(|| str_field(obj.get("dtype"))),
            quantization: obj
                .get("quantization_config")
                .and_then(|q| q.get("quant_method"))
                .and_then(Value::as_str)
                .map(str::to_string),
            hyperparameters,
            has_custom_code: obj.contains_key("auto_map"),
            transformers_version: str_field(obj.get("transformers_version")),
        })
    }
}

/// A PEFT adapter configuration (`adapter_config.json`).
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct AdapterConfig {
    /// The base model this adapter applies to.
    pub base_model: Option<String>,
    /// PEFT method (e.g. `LORA`).
    pub peft_type: Option<String>,
}

impl AdapterConfig {
    /// Parse from `adapter_config.json` content.
    #[must_use]
    pub fn parse(content: &str) -> Option<Self> {
        let v: Value = serde_json::from_str(content).ok()?;
        Some(Self {
            base_model: v
                .get("base_model_name_or_path")
                .and_then(Value::as_str)
                .map(str::to_string),
            peft_type: v
                .get("peft_type")
                .and_then(Value::as_str)
                .map(str::to_string),
        })
    }
}

fn str_field(v: Option<&Value>) -> Option<String> {
    v.and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_config() {
        let config = ModelConfig::parse(
            r#"{
                "model_type": "bert",
                "architectures": ["BertForSequenceClassification"],
                "torch_dtype": "float32",
                "vocab_size": 30522,
                "hidden_size": 768,
                "num_hidden_layers": 12,
                "num_attention_heads": 12,
                "max_position_embeddings": 512,
                "transformers_version": "4.41.0"
            }"#,
        )
        .unwrap();
        assert_eq!(config.model_type.as_deref(), Some("bert"));
        assert_eq!(
            config.architecture.as_deref(),
            Some("BertForSequenceClassification")
        );
        assert_eq!(config.dtype.as_deref(), Some("float32"));
        assert!(!config.has_custom_code);
        assert!(
            config
                .hyperparameters
                .contains(&("context_length".to_string(), "512".to_string()))
        );
    }

    #[test]
    fn v5_dtype_key_and_quantization() {
        let config = ModelConfig::parse(
            r#"{
                "model_type": "llama",
                "dtype": "bfloat16",
                "quantization_config": {"quant_method": "gptq", "bits": 4},
                "auto_map": {"AutoModel": "modeling_custom.CustomModel"}
            }"#,
        )
        .unwrap();
        assert_eq!(config.dtype.as_deref(), Some("bfloat16"));
        assert_eq!(config.quantization.as_deref(), Some("gptq"));
        assert!(config.has_custom_code);
    }

    #[test]
    fn adapter_config() {
        let adapter = AdapterConfig::parse(
            r#"{"base_model_name_or_path": "meta-llama/Llama-3.2-3B", "peft_type": "LORA"}"#,
        )
        .unwrap();
        assert_eq!(
            adapter.base_model.as_deref(),
            Some("meta-llama/Llama-3.2-3B")
        );
        assert_eq!(adapter.peft_type.as_deref(), Some("LORA"));
    }

    #[test]
    fn garbage_is_none() {
        assert!(ModelConfig::parse("not json").is_none());
    }
}
