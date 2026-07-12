//! Assemble a [`NormalizedSbom`] from a [`ModelDescription`].
//!
//! The output shape targets three consumers at once:
//! - the CycloneDX emitter (`emit_cyclonedx`) — modelCard/data/hashes come
//!   out in spec shapes;
//! - this repo's own AI gates (EU AI Act, BSI SBOM-for-AI, NTIA, AI-readiness
//!   scoring) — every machine-derivable required field is populated;
//! - `verify model-weights --model-dir` — weight hashes computed locally are
//!   attached as *authored* baselines on the model component.
//!
//! Facts vs claims: hashes/parameter counts carry a
//! `sbom-tools:aibom:*-source` property (`computed` vs `hub-declared`);
//! model-card content is the author's declaration and is mapped verbatim,
//! never invented. Missing facts land in the [`GenerationReport`].

use chrono::Utc;

use super::description::{FactSource, FileRole, ModelDescription, ModelFile, WeightFormat};
use super::license_map::{MappedLicense, map_hf_license};
use super::report::{GenerationReport, RiskFlag};
use super::{AibomOptions, GeneratedAibom};
use crate::model::{
    Component, ComponentType, Creator, CreatorType, DependencyEdge, DependencyType,
    DocumentMetadata, ExternalRefType, ExternalReference, Hash, HashAlgorithm, MetricEntry,
    MlModelInfo, NormalizedSbom, Organization, Property, SbomFormat,
};

/// Property namespace for generator-provenance facts.
const PROP_NS: &str = "sbom-tools:aibom";
/// CycloneDX AI/ML property-taxonomy namespace.
const CDX_AI_NS: &str = "cdx:ai-ml";

/// Build the SBOM and its generation report.
#[must_use]
pub fn build_sbom(desc: &ModelDescription, options: &AibomOptions) -> GeneratedAibom {
    let mut report = GenerationReport {
        subject: subject_name(desc),
        file_count: desc.files.len(),
        weight_file_count: desc.files.iter().filter(|f| f.role.is_weights()).count(),
        ..GenerationReport::default()
    };

    let mut sbom = NormalizedSbom::new(document_metadata(desc));

    let model = build_model_component(desc, options, &mut report);
    let model_id = model.canonical_id.clone();
    sbom.add_component(model);
    sbom.primary_component_id = Some(model_id.clone());

    for file in &desc.files {
        let component = build_file_component(desc, file, &mut report);
        let file_id = component.canonical_id.clone();
        sbom.add_component(component);
        sbom.add_edge(DependencyEdge::new(
            model_id.clone(),
            file_id,
            DependencyType::DependsOn,
        ));
    }

    for component in sbom.components.values_mut() {
        component.calculate_content_hash();
    }
    sbom.calculate_content_hash();

    GeneratedAibom { sbom, report }
}

/// The display name for the model: repo id, else directory hint.
fn subject_name(desc: &ModelDescription) -> String {
    desc.id
        .clone()
        .or_else(|| desc.name_hint.clone())
        .unwrap_or_else(|| "model".to_string())
}

/// Document-level metadata: timestamp, serial number, tool + author creators.
fn document_metadata(desc: &ModelDescription) -> DocumentMetadata {
    let mut creators = vec![Creator {
        creator_type: CreatorType::Tool,
        name: format!("sbom-tools {}", env!("CARGO_PKG_VERSION")),
        email: None,
    }];
    if let Some(author) = &desc.author {
        creators.push(Creator {
            creator_type: CreatorType::Organization,
            name: author.clone(),
            email: None,
        });
    }

    DocumentMetadata {
        format: SbomFormat::CycloneDx,
        format_version: "1.7".to_string(),
        spec_version: "1.7".to_string(),
        serial_number: Some(format!("urn:uuid:{}", uuid::Uuid::new_v4())),
        created: Utc::now(),
        creators,
        name: Some(subject_name(desc)),
        ..DocumentMetadata::default()
    }
}

/// Build the primary `machine-learning-model` component.
fn build_model_component(
    desc: &ModelDescription,
    options: &AibomOptions,
    report: &mut GenerationReport,
) -> Component {
    let name = subject_name(desc);
    let format_id = desc
        .purl()
        .unwrap_or_else(|| format!("aibom:{name}"));

    let mut component = Component::new(name.clone(), format_id);
    component.component_type = ComponentType::MachineLearningModel;

    if let Some(purl) = desc.purl() {
        component.set_purl(purl);
    } else {
        report.unknown(
            "identifier (purl)",
            "no HuggingFace repo id detected; pass a cache directory or use --model-id",
        );
    }

    match &desc.revision {
        Some(rev) => {
            component = component.with_version(rev.clone());
            if !desc.revision_pinned {
                report.risk(RiskFlag::UnpinnedRevision);
            }
        }
        None => {
            report.unknown(
                "version (revision)",
                "no commit sha detected in the directory layout; pass --revision",
            );
        }
    }

    if let Some(author) = &desc.author {
        component.supplier = Some(Organization::new(author.clone()));
        component.author = Some(author.clone());
    } else {
        report.unknown(
            "supplier/author",
            "no owning organization derivable from the source",
        );
    }

    apply_license(&mut component, desc, report);
    apply_external_refs(&mut component, desc);
    component.ml_model = Some(build_ml_info(desc, report));
    apply_model_properties(&mut component, desc, options, report);

    // Weight hashes on the model component: the AI-010 integrity check, the
    // BSI model-hash element, and `verify model-weights` all read them here.
    for file in desc.files.iter().filter(|f| f.role.is_weights()) {
        let Some(sha256) = &file.sha256 else { continue };
        let hash = match file.hash_source {
            Some(FactSource::HubDeclared) => {
                Hash::enriched(HashAlgorithm::Sha256, sha256.clone())
            }
            _ => Hash::new(HashAlgorithm::Sha256, sha256.clone()),
        };
        component.hashes.push(hash);
    }
    if component.hashes.is_empty() {
        report.unknown(
            "model weight hashes",
            "no weight file carried or produced a SHA-256 (see --no-hash)",
        );
    }

    if desc.config.as_ref().is_some_and(|c| c.has_custom_code) {
        report.risk(RiskFlag::CustomCode("config.json auto_map".to_string()));
    }
    if let Some(gated) = &desc.gated {
        report.risk(RiskFlag::GatedModel(gated.clone()));
    }

    component
}

/// Map the declared license (card first, Hub API second) onto the component.
fn apply_license(
    component: &mut Component,
    desc: &ModelDescription,
    report: &mut GenerationReport,
) {
    let card = desc.card.as_ref();
    let tag = card
        .and_then(|c| c.license.clone())
        .or_else(|| desc.hub_license.clone());

    let mapped = tag.as_deref().and_then(|t| {
        map_hf_license(
            t,
            card.and_then(|c| c.license_name.as_deref()),
            card.and_then(|c| c.license_link.as_deref()),
        )
    });

    match mapped {
        Some(mapped) => {
            if let Some(url) = mapped.url() {
                component.external_refs.push(ExternalReference {
                    ref_type: ExternalRefType::License,
                    url: url.to_string(),
                    comment: Some("declared license text".to_string()),
                    hashes: Vec::new(),
                });
            }
            component
                .licenses
                .add_declared(mapped.into_expression());
        }
        None => {
            report.risk(RiskFlag::MissingLicense);
            report.unknown(
                "license",
                "model card declares no usable license tag; document the license upstream",
            );
        }
    }
}

/// Model-level external references (model card, VCS, distribution).
fn apply_external_refs(component: &mut Component, desc: &ModelDescription) {
    let Some(hub_url) = desc.hub_url() else {
        return;
    };
    let mut push = |ref_type: ExternalRefType, url: String, comment: &str| {
        component.external_refs.push(ExternalReference {
            ref_type,
            url,
            comment: Some(comment.to_string()),
            hashes: Vec::new(),
        });
    };
    push(
        ExternalRefType::ModelCard,
        hub_url.clone(),
        "HuggingFace model card",
    );
    push(ExternalRefType::Vcs, hub_url.clone(), "model repository");
    let dist = match &desc.revision {
        Some(rev) => format!("{hub_url}/tree/{rev}"),
        None => hub_url,
    };
    push(
        ExternalRefType::BinaryDistribution,
        dist,
        "model artifacts at the documented revision",
    );
}

/// Typed model-card information for the modelCard emission and the AI gates.
fn build_ml_info(desc: &ModelDescription, report: &mut GenerationReport) -> MlModelInfo {
    let card = desc.card.as_ref();
    let config = desc.config.as_ref();

    let task = card
        .and_then(|c| c.pipeline_tag.clone())
        .or_else(|| desc.hub_pipeline_tag.clone());

    let mut use_cases = Vec::new();
    if let Some(text) = card.and_then(|c| c.intended_use_text.clone()) {
        use_cases.push(text);
    }
    if let Some(tag) = &task {
        let humanized = tag.replace('-', " ");
        if !use_cases
            .iter()
            .any(|u| u.to_lowercase().contains(&humanized))
        {
            use_cases.push(format!("Declared task: {humanized}"));
        }
    }
    if use_cases.is_empty() {
        report.unknown(
            "intended use",
            "no pipeline tag or intended-use section in the model card",
        );
    }

    let limitations = card.and_then(|c| c.limitations_text.clone());
    if limitations.is_none() {
        report.unknown(
            "limitations",
            "model card has no limitations/bias section",
        );
    }

    let training_datasets: Vec<crate::model::DatasetRef> = card
        .map(|c| {
            c.datasets
                .iter()
                .map(|name| crate::model::DatasetRef {
                    reference: None,
                    name: Some(name.clone()),
                    purl: None,
                })
                .collect()
        })
        .unwrap_or_default();
    if training_datasets.is_empty() {
        report.unknown(
            "training datasets",
            "model card declares no datasets (frontmatter `datasets:`)",
        );
    }

    let performance_metrics: Vec<MetricEntry> = card
        .map(|c| {
            c.metrics
                .iter()
                .map(|m| MetricEntry {
                    metric_type: m.metric_type.clone(),
                    value: m.value.clone(),
                    slice: m.dataset.clone(),
                })
                .collect()
        })
        .unwrap_or_default();
    if performance_metrics.is_empty() {
        report.unknown(
            "evaluation metrics",
            "model card has no model-index evaluation results",
        );
    }

    report.unknown(
        "training energy (kWh)",
        "HuggingFace metadata does not declare training energy; \
         CO2 declarations (if any) are carried as a property",
    );

    MlModelInfo {
        approach: None,
        architecture_family: config.and_then(|c| c.model_type.clone()),
        architecture_name: config.and_then(|c| c.architecture.clone()),
        task,
        quantization: config.and_then(|c| c.quantization.clone()),
        limitations,
        training_datasets,
        energy_kwh_training: None,
        model_card_url: desc.hub_url(),
        use_cases,
        performance_metrics,
        ..MlModelInfo::default()
    }
}

/// Model-component properties: the `cdx:ai-ml` taxonomy plus generator
/// provenance facts.
fn apply_model_properties(
    component: &mut Component,
    desc: &ModelDescription,
    options: &AibomOptions,
    report: &mut GenerationReport,
) {
    let props = &mut component.extensions.properties;
    let mut push = |name: String, value: String| {
        props.push(Property { name, value });
    };

    if let Some(st) = &desc.safetensors {
        push(
            format!("{CDX_AI_NS}:model:parameter:count"),
            st.param_count.to_string(),
        );
        if let Some(source) = desc.param_source {
            push(
                format!("{PROP_NS}:parameter-count-source"),
                source.label().to_string(),
            );
        }
        if let Some(dtype) = st.dominant_dtype() {
            push(
                format!("{CDX_AI_NS}:model:hyperparameter:dtype"),
                dtype.to_string(),
            );
        }
    } else if let Some(dtype) = desc.config.as_ref().and_then(|c| c.dtype.clone()) {
        push(
            format!("{CDX_AI_NS}:model:hyperparameter:dtype"),
            dtype,
        );
    }

    if let Some(config) = &desc.config {
        for (key, value) in &config.hyperparameters {
            push(
                format!("{CDX_AI_NS}:model:hyperparameter:{key}"),
                value.clone(),
            );
        }
        if let Some(quant) = &config.quantization {
            push(
                format!("{CDX_AI_NS}:model:hyperparameter:quantization"),
                quant.clone(),
            );
        }
    }

    if let Some(card) = &desc.card {
        if !card.languages.is_empty() {
            push(
                format!("{CDX_AI_NS}:model:languages"),
                card.languages.join(","),
            );
        }
        if let Some(library) = &card.library_name {
            push(format!("{PROP_NS}:library"), library.clone());
        }
        if let Some(co2) = card.co2_eq_emissions_g {
            push(format!("{PROP_NS}:co2-eq-emissions-g"), co2.to_string());
        }
        // Base-model lineage as declared facts; pedigree emission is a
        // follow-up (the canonical model has no pedigree yet).
        for base in &card.base_model {
            push(format!("{PROP_NS}:base-model"), base.clone());
        }
        if let Some(relation) = &card.base_model_relation {
            push(format!("{PROP_NS}:base-model-relation"), relation.clone());
        }
    }

    if let Some(adapter) = &desc.adapter {
        if let Some(base) = &adapter.base_model {
            push(format!("{PROP_NS}:base-model"), base.clone());
        }
        if let Some(peft) = &adapter.peft_type {
            push(format!("{PROP_NS}:adapter-type"), peft.clone());
        }
    }

    if options.dataset_sensitivity.is_some() && desc.card.as_ref().is_none_or(|c| c.datasets.is_empty()) {
        report.unknown(
            "dataset sensitivity",
            "--dataset-sensitivity was given but no datasets are declared to apply it to",
        );
    } else if let Some(sensitivity) = &options.dataset_sensitivity {
        // Datasets are inline modelCard references in this phase (they have
        // no independent version/identity); the operator assertion is carried
        // as a model property until datasets become first-class components.
        push(
            format!("{PROP_NS}:dataset-sensitivity"),
            sensitivity.clone(),
        );
    }
}

/// Build one per-file component.
fn build_file_component(
    desc: &ModelDescription,
    file: &ModelFile,
    report: &mut GenerationReport,
) -> Component {
    let format_id = desc
        .file_purl(&file.rel_path)
        .unwrap_or_else(|| format!("aibom:file:{}", file.rel_path));
    let mut component = Component::new(file.rel_path.clone(), format_id);

    // Weights and configuration are data; code and docs are files.
    component.component_type = match file.role {
        FileRole::Weights(_) | FileRole::Config => ComponentType::Data,
        FileRole::Code | FileRole::Doc | FileRole::Other => ComponentType::File,
    };

    if let Some(purl) = desc.file_purl(&file.rel_path) {
        component.set_purl(purl);
    }
    if let Some(rev) = &desc.revision {
        component = component.with_version(rev.clone());
    }
    if let Some(author) = &desc.author {
        component.supplier = Some(Organization::new(author.clone()));
        component.author = Some(author.clone());
    }
    // Repo files are distributed under the model's declared license.
    component.licenses = desc
        .card
        .as_ref()
        .and_then(|c| c.license.as_deref())
        .and_then(|tag| {
            map_hf_license(
                tag,
                desc.card.as_ref().and_then(|c| c.license_name.as_deref()),
                desc.card.as_ref().and_then(|c| c.license_link.as_deref()),
            )
        })
        .map(|mapped| {
            let mut licenses = crate::model::LicenseInfo::default();
            licenses.add_declared(match mapped {
                MappedLicense::Spdx(id) => crate::model::LicenseExpression::from_spdx_id(&id),
                MappedLicense::Named { name, .. } => crate::model::LicenseExpression::new(name),
            });
            licenses
        })
        .unwrap_or_default();

    if let Some(sha256) = &file.sha256 {
        let source = file.hash_source.unwrap_or(FactSource::Computed);
        let hash = match source {
            FactSource::HubDeclared => Hash::enriched(HashAlgorithm::Sha256, sha256.clone()),
            FactSource::Computed => Hash::new(HashAlgorithm::Sha256, sha256.clone()),
        };
        component.hashes.push(hash);
        component.extensions.properties.push(Property {
            name: format!("{PROP_NS}:hash-source"),
            value: source.label().to_string(),
        });
        report.count_hash(source);
    }

    if let Some(size) = file.size {
        component.extensions.properties.push(Property {
            name: format!("{PROP_NS}:file-size-bytes"),
            value: size.to_string(),
        });
    }
    component.extensions.properties.push(Property {
        name: format!("{PROP_NS}:file-role"),
        value: role_label(file.role).to_string(),
    });

    match file.role {
        FileRole::Weights(WeightFormat::Pickle) => {
            report.risk(RiskFlag::PickleWeights(file.rel_path.clone()));
        }
        FileRole::Code => {
            report.risk(RiskFlag::CustomCode(file.rel_path.clone()));
        }
        _ => {}
    }

    component
}

/// Stable `sbom-tools:aibom:file-role` property value.
const fn role_label(role: FileRole) -> &'static str {
    match role {
        FileRole::Weights(WeightFormat::Safetensors) => "weights/safetensors",
        FileRole::Weights(WeightFormat::Gguf) => "weights/gguf",
        FileRole::Weights(WeightFormat::Pickle) => "weights/pickle",
        FileRole::Weights(WeightFormat::Onnx) => "weights/onnx",
        FileRole::Weights(WeightFormat::Tensorflow) => "weights/tensorflow",
        FileRole::Weights(WeightFormat::Flax) => "weights/flax",
        FileRole::Weights(_) => "weights/other",
        FileRole::Config => "config",
        FileRole::Code => "code",
        FileRole::Doc => "doc",
        FileRole::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aibom::card::ModelCard;
    use crate::aibom::config_json::ModelConfig;

    fn demo_description() -> ModelDescription {
        let card = ModelCard::parse(
            "---\nlicense: apache-2.0\ndatasets: [imdb]\npipeline_tag: text-classification\n\
             model-index:\n- name: m\n  results:\n  - task: {type: t}\n    dataset: {name: imdb}\n\
             metrics: []\n---\n## Limitations\nEnglish only.\n",
        );
        ModelDescription {
            id: Some("demo-org/tiny".to_string()),
            revision: Some("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0".to_string()),
            revision_pinned: true,
            author: Some("demo-org".to_string()),
            card,
            config: ModelConfig::parse(
                r#"{"model_type": "bert", "architectures": ["BertModel"], "vocab_size": 100}"#,
            ),
            files: vec![
                ModelFile {
                    rel_path: "model.safetensors".into(),
                    size: Some(1000),
                    role: FileRole::Weights(WeightFormat::Safetensors),
                    sha256: Some("ab".repeat(32)),
                    hash_source: Some(FactSource::Computed),
                },
                ModelFile {
                    rel_path: "config.json".into(),
                    size: Some(40),
                    role: FileRole::Config,
                    sha256: Some("cd".repeat(32)),
                    hash_source: Some(FactSource::Computed),
                },
            ],
            source_desc: "test".into(),
            ..ModelDescription::default()
        }
    }

    #[test]
    fn model_component_shape() {
        let generated = build_sbom(&demo_description(), &AibomOptions::default());
        let sbom = &generated.sbom;
        let model = sbom
            .get_component(sbom.primary_component_id.as_ref().unwrap())
            .unwrap();

        assert_eq!(model.component_type, ComponentType::MachineLearningModel);
        assert_eq!(
            model.identifiers.purl.as_deref(),
            Some("pkg:huggingface/demo-org/tiny@a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0")
        );
        assert_eq!(model.hashes.len(), 1, "one weight hash on the model");
        let ml = model.ml_model.as_ref().unwrap();
        assert_eq!(ml.task.as_deref(), Some("text-classification"));
        assert_eq!(ml.architecture_family.as_deref(), Some("bert"));
        assert_eq!(ml.training_datasets.len(), 1);
        assert!(ml.limitations.as_deref().unwrap().contains("English"));
        assert!(!ml.use_cases.is_empty());
        assert!(!model.licenses.declared.is_empty());
    }

    #[test]
    fn file_components_and_edges() {
        let generated = build_sbom(&demo_description(), &AibomOptions::default());
        let sbom = &generated.sbom;
        assert_eq!(sbom.components.len(), 3);
        assert_eq!(sbom.edges.len(), 2);
        let weights = sbom
            .components
            .values()
            .find(|c| c.name == "model.safetensors")
            .unwrap();
        assert_eq!(weights.component_type, ComponentType::Data);
        assert!(weights.dataset.is_none(), "weight files are not datasets");
        assert_eq!(weights.hashes.len(), 1);
        assert!(
            weights
                .identifiers
                .purl
                .as_deref()
                .unwrap()
                .ends_with("#model.safetensors")
        );
    }

    #[test]
    fn report_counts_and_unknowns() {
        let generated = build_sbom(&demo_description(), &AibomOptions::default());
        assert_eq!(generated.report.file_count, 2);
        assert_eq!(generated.report.weight_file_count, 1);
        assert_eq!(generated.report.computed_hashes, 2);
        // Metrics are declared empty in the fixture card → known unknown.
        assert!(
            generated
                .report
                .known_unknowns
                .iter()
                .any(|k| k.field.contains("metrics"))
        );
    }

    #[test]
    fn missing_everything_is_reported_not_fabricated() {
        let desc = ModelDescription {
            name_hint: Some("mystery".to_string()),
            files: vec![ModelFile {
                rel_path: "model.bin".into(),
                size: None,
                role: FileRole::Weights(WeightFormat::Pickle),
                sha256: None,
                hash_source: None,
            }],
            source_desc: "test".into(),
            ..ModelDescription::default()
        };
        let generated = build_sbom(&desc, &AibomOptions::default());
        let sbom = &generated.sbom;
        let model = sbom
            .get_component(sbom.primary_component_id.as_ref().unwrap())
            .unwrap();
        assert_eq!(model.name, "mystery");
        assert!(model.identifiers.purl.is_none());
        assert!(model.version.is_none());
        assert!(model.licenses.declared.is_empty());
        assert!(
            generated
                .report
                .risks
                .contains(&RiskFlag::PickleWeights("model.bin".into()))
        );
        assert!(generated.report.risks.contains(&RiskFlag::MissingLicense));
        let fields: Vec<_> = generated
            .report
            .known_unknowns
            .iter()
            .map(|k| k.field.as_str())
            .collect();
        assert!(fields.iter().any(|f| f.contains("purl")));
        assert!(fields.iter().any(|f| f.contains("version")));
    }
}
